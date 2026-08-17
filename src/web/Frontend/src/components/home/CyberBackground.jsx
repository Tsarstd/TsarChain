import { useEffect, useRef } from "react";

const getRandom = () => {
  const array = new Uint32Array(1);
  globalThis.crypto.getRandomValues(array);
  return array[0] / 0x100000000;
};

const drawCyberGrid = (ctx, width, height, gridSize = 72) => {
  ctx.lineWidth = 0.5;
  ctx.strokeStyle = "rgba(255, 255, 255, 0.025)";

  for (let x = 0; x < width; x += gridSize) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }

  for (let y = 0; y < height; y += gridSize) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }
};

const drawScanBeam = (ctx, width, scanlineY) => {
  const scanGradient = ctx.createLinearGradient(0, scanlineY - 40, 0, scanlineY + 40);
  scanGradient.addColorStop(0, "rgba(224, 95, 50, 0)");
  scanGradient.addColorStop(0.5, "rgba(224, 95, 50, 0.035)");
  scanGradient.addColorStop(1, "rgba(224, 95, 50, 0)");

  ctx.fillStyle = scanGradient;
  ctx.fillRect(0, scanlineY - 40, width, 80);
};

const drawConstellationLines = (ctx, particles, maxDistance = 140) => {
  const maxDistSq = maxDistance * maxDistance;
  for (let i = 0; i < particles.length; i++) {
    const p1 = particles[i];
    for (let j = i + 1; j < particles.length; j++) {
      const p2 = particles[j];
      const dx = p1.x - p2.x;
      const dy = p1.y - p2.y;
      const distSq = dx * dx + dy * dy;

      if (distSq < maxDistSq) {
        const dist = Math.sqrt(distSq);
        const lineAlpha = (1 - dist / maxDistance) * 0.14;
        ctx.strokeStyle = `rgba(224, 95, 50, ${lineAlpha})`;
        ctx.lineWidth = 0.75;
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      }
    }
  }
};

const updateParticlePosition = (p, width, height, mouse) => {
  p.x += p.vx;
  p.y += p.vy;

  if (p.x < 0 || p.x > width) p.vx *= -1;
  if (p.y < 0 || p.y > height) p.vy *= -1;

  if (mouse.active) {
    const mdx = p.x - mouse.x;
    const mdy = p.y - mouse.y;
    const mdistSq = mdx * mdx + mdy * mdy;
    const maxMouseDist = 160;
    if (mdistSq < maxMouseDist * maxMouseDist && mdistSq > 0) {
      const mdist = Math.sqrt(mdistSq);
      const force = (maxMouseDist - mdist) / maxMouseDist;
      p.x += (mdx / mdist) * force * 1.5;
      p.y += (mdy / mdist) * force * 1.5;
    }
  }
};

const renderParticle = (ctx, p) => {
  p.pulseVal += p.pulseSpeed;
  const currentAlpha = p.alpha + Math.sin(p.pulseVal) * 0.15;

  ctx.fillStyle = p.color;
  ctx.globalAlpha = Math.max(0.1, Math.min(1, currentAlpha));
  ctx.beginPath();
  ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
  ctx.fill();

  if (p.radius > 1.8) {
    ctx.fillStyle = p.color;
    ctx.globalAlpha = currentAlpha * 0.25;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.radius * 3, 0, Math.PI * 2);
    ctx.fill();
  }
};

const updateAndDrawParticles = (ctx, particles, width, height, mouse) => {
  for (const p of particles) {
    updateParticlePosition(p, width, height, mouse);
    renderParticle(ctx, p);
  }
};

const CyberBackground = () => {
  const canvasRef = useRef(null);
  const mouseRef = useRef({ x: -1000, y: -1000, active: false });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId;
    let isPaused = false;
    let width = (canvas.width = globalThis.innerWidth);
    let height = (canvas.height = globalThis.innerHeight);

    // Respect reduced motion preference
    const prefersReducedMotion = Boolean(globalThis.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches);

    // Particles configuration optimized for performance
    const isMobile = width < 768;
    const maxParticles = isMobile ? 25 : 55;
    const particleCount = prefersReducedMotion ? 0 : Math.min(Math.floor((width * height) / 22000), maxParticles);
    const particles = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: getRandom() * width,
        y: getRandom() * height,
        vx: (getRandom() - 0.5) * 0.45,
        vy: (getRandom() - 0.5) * 0.45,
        radius: getRandom() * 2 + 0.8,
        alpha: getRandom() * 0.5 + 0.2,
        color: getRandom() > 0.25 ? "#e05f32" : "#ff7a45",
        pulseSpeed: getRandom() * 0.02 + 0.008,
        pulseVal: getRandom() * Math.PI,
      });
    }

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = globalThis.innerWidth;
      height = canvas.height = globalThis.innerHeight;
      if (prefersReducedMotion) {
        ctx.clearRect(0, 0, width, height);
        drawCyberGrid(ctx, width, height);
      }
    };

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        active: true,
      };
    };

    const handleMouseLeave = () => {
      mouseRef.current = { x: -1000, y: -1000, active: false };
    };

    // Pause rendering loop when tab is in background to save CPU and battery
    const handleVisibilityChange = () => {
      if (document.hidden) {
        isPaused = true;
        if (animationFrameId) {
          cancelAnimationFrame(animationFrameId);
        }
      } else {
        isPaused = false;
        if (!prefersReducedMotion) {
          animationFrameId = requestAnimationFrame(render);
        }
      }
    };

    globalThis.addEventListener("resize", handleResize);
    globalThis.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseleave", handleMouseLeave);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    let scanlineY = 0;

    const render = () => {
      if (isPaused) return;

      ctx.clearRect(0, 0, width, height);

      // 1. Subtle Cyber Grid
      drawCyberGrid(ctx, width, height);

      if (!prefersReducedMotion) {
        // 2. Faint Scanning Light Beam
        scanlineY += 0.8;
        if (scanlineY > height + 100) {
          scanlineY = -100;
        }
        drawScanBeam(ctx, width, scanlineY);

        // 3. Connective Constellation Lines
        drawConstellationLines(ctx, particles);

        // 4. Update & Render Particles
        updateAndDrawParticles(ctx, particles, width, height, mouseRef.current);

        ctx.globalAlpha = 1;
        animationFrameId = requestAnimationFrame(render);
      }
    };

    if (prefersReducedMotion) {
      drawCyberGrid(ctx, width, height);
    } else {
      render();
    }

    return () => {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
      globalThis.removeEventListener("resize", handleResize);
      globalThis.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseleave", handleMouseLeave);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      tabIndex={-1}
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: 0,
      }}
      aria-hidden="true"
    />
  );
};

export default CyberBackground;
