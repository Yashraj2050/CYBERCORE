import math
import os
import subprocess
import sys

def main():
    width = 1280
    height = 720
    fps = 30
    duration = 5
    total_frames = fps * duration
    
    output_mp4 = "frontend/public/videos/cybercore-hero-bg.mp4"
    poster_jpg = "frontend/public/videos/cybercore-hero-poster.jpg"
    
    print(f"Generating cinematic video: {width}x{height} @ {fps}fps, {total_frames} frames...")
    
    # Precompute network constellation nodes
    import random
    random.seed(42)
    
    nodes = []
    num_nodes = 24
    for i in range(num_nodes):
        nodes.append({
            "base_x": random.uniform(width * 0.1, width * 0.9),
            "base_y": random.uniform(height * 0.15, height * 0.85),
            "radius": random.uniform(2.5, 4.5),
            "freq_x": random.uniform(1.0, 3.0),
            "freq_y": random.uniform(1.0, 3.0),
            "phase": random.uniform(0, math.pi * 2),
            "cyan": random.random() > 0.4
        })
        
    edges = []
    for i in range(num_nodes):
        for j in range(i + 1, num_nodes):
            dx = nodes[i]["base_x"] - nodes[j]["base_x"]
            dy = nodes[i]["base_y"] - nodes[j]["base_y"]
            dist = math.hypot(dx, dy)
            if dist < 260:
                edges.append((i, j, dist))
                
    # FFmpeg pipe
    cmd = [
        "ffmpeg",
        "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-s", f"{width}x{height}",
        "-pix_fmt", "rgb24",
        "-r", str(fps),
        "-i", "-",
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-preset", "faster",
        "-crf", "22",
        "-movflags", "+faststart",
        output_mp4
    ]
    
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # We will build frames
    # Base background: deep obsidian gradient with dark blue ambient center
    base_bg = bytearray(width * height * 3)
    for y in range(height):
        ny = (y - height * 0.45) / (height * 0.6)
        row_offset = y * width * 3
        for x in range(width):
            nx = (x - width * 0.5) / (width * 0.6)
            rad2 = nx * nx + ny * ny
            # Subtle deep midnight #080A10 -> ambient center #0E1528
            glow = max(0.0, 1.0 - rad2 * 0.5)
            r = int(7 + 5 * glow)
            g = int(9 + 10 * glow)
            b = int(14 + 22 * glow)
            idx = row_offset + x * 3
            base_bg[idx] = r
            base_bg[idx+1] = g
            base_bg[idx+2] = b

    first_frame_saved = False

    for f in range(total_frames):
        t = (f / total_frames) * math.pi * 2 # perfectly periodic in [0, 2pi]
        frame = bytearray(base_bg)
        
        # Current node positions for this frame
        cur_nodes = []
        for n in nodes:
            x = n["base_x"] + 12 * math.sin(t + n["phase"])
            y = n["base_y"] + 8 * math.cos(t + n["phase"])
            cur_nodes.append((x, y))
            
        # Draw edges (anti-aliased dim lines)
        for (i, j, dist) in edges:
            x1, y1 = cur_nodes[i]
            x2, y2 = cur_nodes[j]
            # pulse intensity along the edge
            pulse = 0.5 + 0.5 * math.sin(t * 2 + (i + j))
            alpha = (1.0 - dist / 260.0) * (0.2 + 0.3 * pulse)
            
            # Step along edge
            steps = int(dist / 2.0)
            if steps > 0:
                for s in range(steps):
                    frac = s / steps
                    px = int(x1 + (x2 - x1) * frac)
                    py = int(y1 + (y2 - y1) * frac)
                    if 0 <= px < width and 0 <= py < height:
                        idx = (py * width + px) * 3
                        # Color: cyan/electric blue line
                        cr = int(30 * alpha)
                        cg = int(90 * alpha)
                        cb = int(180 * alpha)
                        frame[idx] = min(255, frame[idx] + cr)
                        frame[idx+1] = min(255, frame[idx+1] + cg)
                        frame[idx+2] = min(255, frame[idx+2] + cb)

        # Draw glowing packets traveling along selected edges
        for idx_e, (i, j, dist) in enumerate(edges[:12]):
            x1, y1 = cur_nodes[i]
            x2, y2 = cur_nodes[j]
            # Packet travels back and forth seamlessly with sin
            pkt_progress = 0.5 + 0.5 * math.sin(t * 3 + idx_e * 0.7)
            px = int(x1 + (x2 - x1) * pkt_progress)
            py = int(y1 + (y2 - y1) * pkt_progress)
            
            for ox in range(-2, 3):
                for oy in range(-2, 3):
                    gx = px + ox
                    gy = py + oy
                    if 0 <= gx < width and 0 <= gy < height:
                        d2 = ox * ox + oy * oy
                        g_alpha = max(0.0, 1.0 - d2 / 5.0)
                        if g_alpha > 0:
                            p_idx = (gy * width + gx) * 3
                            # Electric cyan #00E5FF glow
                            frame[p_idx] = min(255, frame[p_idx] + int(20 * g_alpha))
                            frame[p_idx+1] = min(255, frame[p_idx+1] + int(180 * g_alpha))
                            frame[p_idx+2] = min(255, frame[p_idx+2] + int(240 * g_alpha))

        # Draw nodes
        for idx_n, (x, y) in enumerate(cur_nodes):
            ix = int(x)
            iy = int(y)
            is_cyan = nodes[idx_n]["cyan"]
            r_glow = 4
            for ox in range(-r_glow, r_glow + 1):
                for oy in range(-r_glow, r_glow + 1):
                    gx = ix + ox
                    gy = iy + oy
                    if 0 <= gx < width and 0 <= gy < height:
                        d2 = ox * ox + oy * oy
                        if d2 <= r_glow * r_glow:
                            g_val = max(0.0, 1.0 - d2 / (r_glow * r_glow))
                            p_idx = (gy * width + gx) * 3
                            if is_cyan:
                                frame[p_idx] = min(255, frame[p_idx] + int(40 * g_val))
                                frame[p_idx+1] = min(255, frame[p_idx+1] + int(180 * g_val))
                                frame[p_idx+2] = min(255, frame[p_idx+2] + int(240 * g_val))
                            else:
                                frame[p_idx] = min(255, frame[p_idx] + int(50 * g_val))
                                frame[p_idx+1] = min(255, frame[p_idx+1] + int(100 * g_val))
                                frame[p_idx+2] = min(255, frame[p_idx+2] + int(255 * g_val))
                                
        proc.stdin.write(frame)
        
        # Save first frame as PPM to convert to poster JPG
        if not first_frame_saved:
            with open("/tmp/hero_poster.ppm", "wb") as pf:
                pf.write(f"P6\n{width} {height}\n255\n".encode())
                pf.write(frame)
            first_frame_saved = True

    proc.stdin.close()
    proc.wait()
    print("Video encoding complete.")
    
    # Convert poster PPM to JPG
    subprocess.run(["ffmpeg", "-y", "-i", "/tmp/hero_poster.ppm", "-q:v", "2", poster_jpg], check=True)
    if os.path.exists("/tmp/hero_poster.ppm"):
        os.remove("/tmp/hero_poster.ppm")
    print(f"Poster image saved: {poster_jpg}")

if __name__ == "__main__":
    main()

