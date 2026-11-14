"""
esp_lab.py — ESP *simulator* for game-security auditing.

Targets MockMemory only. There is no OpenProcess/ReadProcessMemory anywhere
in this file, and none should be added: to audit a real build, feed the same
functions from an in-engine debug dump or a captured replication stream.

    pip install pygame numpy
    python esp_lab.py

Controls: WASD move, arrows look, SPACE/CTRL up/down,
          H toggle server-side visibility culling, ESC quit.
"""

import math
import numpy as np
import pygame

WIDTH, HEIGHT = 1280, 720
FOV_Y = math.radians(70.0)
NEAR, FAR = 0.1, 500.0
LOCAL_TEAM = 0

# ---------------------------------------------------------------- memory model
class MockMemory:
    """Byte-addressable stand-in for a process's address space."""
    def __init__(self, base=0x7FF600000000):
        self.mem, self.base, self._next = {}, base, base + 0x1000

    def alloc(self, size=0x1000):
        addr = self._next
        self._next += (size + 0xFFF) & ~0xFFF
        return addr

    def write_ptr(self, a, v): self.mem[a] = int(v)
    def write_i32(self, a, v): self.mem[a] = int(v)
    def write_f32(self, a, v): self.mem[a] = float(v)

    def read_ptr(self, a): return int(self.mem.get(a, 0))
    def read_i32(self, a): return int(self.mem.get(a, 0))
    def read_f32(self, a): return float(self.mem.get(a, 0.0))


def write_vec3(mem, addr, v):
    for i, c in enumerate(v):
        mem.write_f32(addr + i * 4, c)


def read_vec3(mem, addr):
    return tuple(mem.read_f32(addr + i * 4) for i in range(3))


# Offsets, mirroring the chain in the doc:
# [[base+0x10A4] + 0x58] -> entity array; entity+0x30 -> health
OFF_ENTITY_LIST = 0x10A4
OFF_LIST_ARRAY  = 0x58
OFF_ENT_COUNT   = 0x20
OFF_HEALTH      = 0x30
OFF_TEAM        = 0x34
OFF_DORMANT     = 0x38
OFF_ORIGIN      = 0x40
OFF_BONES_PTR   = 0x50

# ---------------------------------------------------------------- skeleton
BONE_NAMES = ["head", "neck", "chest", "spine", "pelvis",
              "l_shoulder", "l_elbow", "l_hand",
              "r_shoulder", "r_elbow", "r_hand",
              "l_hip", "l_knee", "l_foot",
              "r_hip", "r_knee", "r_foot"]

BONES_LOCAL = [
    (0.00, 0.00, 1.70), (0.00, 0.00, 1.55), (0.00, 0.00, 1.38),
    (0.00, 0.00, 1.15), (0.00, 0.00, 0.95),
    (0.20, 0.00, 1.45), (0.28, 0.00, 1.18), (0.30, 0.00, 0.92),
    (-0.20, 0.00, 1.45), (-0.28, 0.00, 1.18), (-0.30, 0.00, 0.92),
    (0.11, 0.00, 0.92), (0.12, 0.00, 0.48), (0.12, 0.00, 0.05),
    (-0.11, 0.00, 0.92), (-0.12, 0.00, 0.48), (-0.12, 0.00, 0.05),
]
BONE_LINKS = [(0, 1), (1, 2), (2, 3), (3, 4), (2, 5), (5, 6), (6, 7),
              (2, 8), (8, 9), (9, 10), (4, 11), (11, 12), (12, 13),
              (4, 14), (14, 15), (15, 16)]
HEAD, FOOT_L, FOOT_R = 0, 13, 16

# (x, y, z, width, depth, height) — level geometry, used for occlusion tests
WALLS = [(-8, -6, 0, 4, 12, 3), (6, 2, 0, 5, 3, 3.5), (0, 14, 0, 10, 2, 3)]


def build_world(mem, n=10, seed=7):
    rng = np.random.default_rng(seed)
    base = mem.base
    lst, arr = mem.alloc(), mem.alloc(0x400)
    mem.write_ptr(base + OFF_ENTITY_LIST, lst)
    mem.write_ptr(lst + OFF_LIST_ARRAY, arr)
    mem.write_i32(lst + OFF_ENT_COUNT, n)

    for i in range(n):
        e = mem.alloc()
        mem.write_ptr(arr + i * 8, e)

        pos = (float(rng.uniform(-28, 28)), float(rng.uniform(-20, 28)), 0.0)
        yaw = float(rng.uniform(0, 2 * math.pi))
        write_vec3(mem, e + OFF_ORIGIN, pos)
        mem.write_i32(e + OFF_HEALTH, 100)
        mem.write_i32(e + OFF_TEAM, i % 2)      # half are on your team
        mem.write_i32(e + OFF_DORMANT, 0)

        bones = mem.alloc(0x200)
        mem.write_ptr(e + OFF_BONES_PTR, bones)
        ca, sa = math.cos(yaw), math.sin(yaw)
        for j, (bx, by, bz) in enumerate(BONES_LOCAL):
            write_vec3(mem, bones + j * 12,
                       (pos[0] + bx * ca - by * sa,
                        pos[1] + bx * sa + by * ca,
                        pos[2] + bz))


# ---------------------------------------------------------------- the "cheat"
class ESPPipeline:
    """Reads MockMemory exactly as a memory-reading cheat would."""

    def __init__(self, mem):
        self.mem, self.base = mem, mem.base

    def entity_list(self):
        m = self.mem
        struct = m.read_ptr(self.base + OFF_ENTITY_LIST)      # [base+0x10A4]
        if not struct:
            return []
        arr = m.read_ptr(struct + OFF_LIST_ARRAY)             # +0x58
        count = m.read_i32(struct + OFF_ENT_COUNT)
        out = []
        for i in range(count):
            e = m.read_ptr(arr + i * 8)
            if e:
                out.append(e)
        return out

    def snapshot(self):
        rows = []
        for e in self.entity_list():
            if self.mem.read_i32(e + OFF_DORMANT):            # filter 1
                continue
            if self.mem.read_i32(e + OFF_TEAM) == LOCAL_TEAM: # filter 2
                continue
            if self.mem.read_i32(e + OFF_HEALTH) <= 0:        # filter 3
                continue
            bp = self.mem.read_ptr(e + OFF_BONES_PTR)
            rows.append({
                "origin": read_vec3(self.mem, e + OFF_ORIGIN),
                "health": self.mem.read_i32(e + OFF_HEALTH),
                "bones": [read_vec3(self.mem, bp + i * 12)
                          for i in range(len(BONE_NAMES))],
            })
        return rows


# ---------------------------------------------------------------- projection
def make_view(eye, yaw, pitch):
    f = np.array([math.cos(pitch) * math.cos(yaw),
                  math.cos(pitch) * math.sin(yaw),
                  math.sin(pitch)])
    r = np.array([math.sin(yaw), -math.cos(yaw), 0.0])
    u = np.cross(r, f)
    return np.array([
        [r[0], r[1], r[2], -r.dot(eye)],
        [u[0], u[1], u[2], -u.dot(eye)],
        [-f[0], -f[1], -f[2], f.dot(eye)],
        [0.0, 0.0, 0.0, 1.0],
    ])


def make_proj():
    aspect = WIDTH / HEIGHT
    t = 1.0 / math.tan(FOV_Y / 2.0)
    return np.array([
        [t / aspect, 0, 0, 0],
        [0, t, 0, 0],
        [0, 0, (FAR + NEAR) / (NEAR - FAR), 2 * FAR * NEAR / (NEAR - FAR)],
        [0, 0, -1, 0],
    ])


def world_to_screen(p, view, proj):
    v = view @ np.array([p[0], p[1], p[2], 1.0])
    if v[2] > -NEAR:
        return None
    c = proj @ v
    w = c[3]
    if w <= 1e-6:
        return None
    ndc = c[:3] / w
    if abs(ndc[0]) > 1.5 or abs(ndc[1]) > 1.5:
        return None
    return ((ndc[0] * 0.5 + 0.5) * WIDTH,
            (1.0 - (ndc[1] * 0.5 + 0.5)) * HEIGHT,
            -v[2])


# ---------------------------------------------------------------- server side
def segment_hits_box(p0, p1, box):
    x, y, z, w, d, h = box
    lo, hi = (x, y, z), (x + w, y + d, z + h)
    tmin, tmax = 0.0, 1.0
    for i in range(3):
        delta = p1[i] - p0[i]
        if abs(delta) < 1e-9:
            if p0[i] < lo[i] or p0[i] > hi[i]:
                return False
        else:
            t1 = (lo[i] - p0[i]) / delta
            t2 = (hi[i] - p0[i]) / delta
            if t1 > t2:
                t1, t2 = t2, t1
            tmin, tmax = max(tmin, t1), min(tmax, t2)
            if tmin > tmax:
                return False
    return True


def replicate(mem, eye):
    """Server-authoritative build: occluded enemies are simply never sent."""
    for e in ESPPipeline(mem).entity_list():
        origin = read_vec3(mem, e + OFF_ORIGIN)
        chest = (origin[0], origin[1], origin[2] + 1.38)
        visible = not any(segment_hits_box(eye, chest, b) for b in WALLS)
        if visible:
            mem.write_i32(e + OFF_DORMANT, 0)
        else:
            mem.write_i32(e + OFF_DORMANT, 1)      # data withheld, not flagged
            write_vec3(mem, e + OFF_ORIGIN, (0, 0, 0))
            bp = mem.read_ptr(e + OFF_BONES_PTR)
            for j in range(len(BONE_NAMES)):
                write_vec3(mem, bp + j * 12, (0, 0, 0))


# ---------------------------------------------------------------- rendering
def draw_walls(screen, view, proj):
    for (x, y, z, w, d, h) in WALLS:
        corners = [(x, y, z), (x + w, y, z), (x + w, y + d, z), (x, y + d, z),
                   (x, y, z + h), (x + w, y, z + h),
                   (x + w, y + d, z + h), (x, y + d, z + h)]
        pts = [world_to_screen(c, view, proj) for c in corners]
        for a, b in [(0, 1), (1, 2), (2, 3), (3, 0), (4, 5), (5, 6),
                     (6, 7), (7, 4), (0, 4), (1, 5), (2, 6), (3, 7)]:
            if pts[a] and pts[b]:
                pygame.draw.line(screen, (55, 55, 65),
                                 pts[a][:2], pts[b][:2], 1)


def draw_esp(screen, font, rows, eye, view, proj):
    for ent in rows:
        pts = [world_to_screen(b, view, proj) for b in ent["bones"]]

        for a, b in BONE_LINKS:
            if pts[a] and pts[b]:
                pygame.draw.line(screen, (0, 220, 255),
                                 pts[a][:2], pts[b][:2], 2)

        head, foot = pts[HEAD], pts[FOOT_L]
        if not (head and foot):
            continue
        top, bottom = head[1] - 14, foot[1]
        h = bottom - top
        if h <= 4:
            continue
        box = pygame.Rect(0, 0, int(h * 0.55), int(h))
        box.midbottom = (int((head[0] + foot[0]) / 2), int(bottom))
        pygame.draw.rect(screen, (255, 80, 80), box, 1)

        hp = max(0, min(ent["health"], 100))
        bar = pygame.Rect(box.left - 6, box.top, 3, box.height)
        pygame.draw.rect(screen, (60, 0, 0), bar)
        pygame.draw.rect(screen, (0, 230, 90),
                         (bar.x, bar.bottom - int(bar.height * hp / 100),
                          bar.width, int(bar.height * hp / 100)))

        pygame.draw.line(screen, (255, 255, 255), (WIDTH // 2, HEIGHT),
                         (box.centerx, box.bottom), 1)

        dist = math.dist(eye, ent["origin"])
        label = font.render(f"{int(dist)}m  {hp}hp", True, (235, 235, 235))
        screen.blit(label, (box.left, box.top - 18))


# ---------------------------------------------------------------- main
def main():
    mem = MockMemory()
    build_world(mem)
    esp = ESPPipeline(mem)

    pygame.init()
    screen = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("ESP lab — mock target only")
    font = pygame.font.SysFont(None, 20)
    clock = pygame.time.Clock()

    eye = np.array([0.0, -24.0, 1.7])
    yaw, pitch = math.radians(90.0), 0.0
    secure = False
    running = True

    while running:
        dt = min(clock.tick(60) / 1000.0, 0.05)
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                running = False
            elif ev.type == pygame.KEYDOWN and ev.key == pygame.K_ESCAPE:
                running = False
            elif ev.type == pygame.KEYDOWN and ev.key == pygame.K_h:
                secure = not secure

        k = pygame.key.get_pressed()
        speed = 12.0 * dt
        fx, fy = math.cos(yaw), math.sin(yaw)
        rx, ry = math.sin(yaw), -math.cos(yaw)
        if k[pygame.K_w]: eye += np.array([fx, fy, 0]) * speed
        if k[pygame.K_s]: eye -= np.array([fx, fy, 0]) * speed
        if k[pygame.K_d]: eye += np.array([rx, ry, 0]) * speed
        if k[pygame.K_a]: eye -= np.array([rx, ry, 0]) * speed
        if k[pygame.K_SPACE]:  eye[2] += speed
        if k[pygame.K_LCTRL]:  eye[2] = max(0.3, eye[2] - speed)
        if k[pygame.K_LEFT]:  yaw -= 1.8 * dt
        if k[pygame.K_RIGHT]: yaw += 1.8 * dt
        if k[pygame.K_UP]:    pitch += 1.4 * dt
        if k[pygame.K_DOWN]:  pitch -= 1.4 * dt
        pitch = max(-math.radians(88), min(math.radians(88), pitch))

        if secure:
            replicate(mem, eye)

        view, proj = make_view(eye, yaw, pitch), make_proj()
        rows = esp.snapshot()

        screen.fill((14, 14, 18))
        draw_walls(screen, view, proj)
        draw_esp(screen, font, rows, eye, view, proj)

        pygame.draw.line(screen, (255, 255, 255),
                         (WIDTH // 2 - 6, HEIGHT // 2),
                         (WIDTH // 2 + 6, HEIGHT // 2))
        pygame.draw.line(screen, (255, 255, 255),
                         (WIDTH // 2, HEIGHT // 2 - 6),
                         (WIDTH // 2, HEIGHT // 2 + 6))

        mode = "SERVER-AUTHORITATIVE (occluded enemies not replicated)" \
            if secure else "LEAKY CLIENT (full entity list, all bone data)"
        colour = (0, 230, 90) if secure else (255, 80, 80)
        screen.blit(font.render(mode, True, colour), (12, 10))
        screen.blit(font.render(
            f"entities visible to cheat: {len(rows)}   [H] toggle  "
            f"[WASD/arrows] move  [ESC] quit", True, (170, 170, 180)), (12, 32))

        pygame.display.flip()

    pygame.quit()


if __name__ == "__main__":
    main()