import { useState, useRef, useEffect, useCallback } from "react";

const FRICTION = 0.94;
const VELOCITY_THRESHOLD = 0.15;
const MAX_VELOCITY = 45;

export const useDragScroll = () => {
  const scrollerRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);

  const animFrameRef = useRef(null);
  const velocityRef = useRef(0);
  const dragRef = useRef({
    isDown: false,
    startX: 0,
    lastX: 0,
    lastTime: 0,
    scrollLeft: 0,
    moved: false,
    wasDrag: false,
  });

  const stopMomentum = useCallback(() => {
    if (animFrameRef.current !== null) {
      cancelAnimationFrame(animFrameRef.current);
      animFrameRef.current = null;
    }
    velocityRef.current = 0;
  }, []);

  const startMomentum = useCallback((initialVelocity) => {
    stopMomentum();
    const clampedVelocity = Math.max(-MAX_VELOCITY, Math.min(MAX_VELOCITY, initialVelocity));
    velocityRef.current = clampedVelocity;

    const step = () => {
      const el = scrollerRef.current;
      if (!el) {
        animFrameRef.current = null;
        return;
      }

      el.scrollLeft -= velocityRef.current;
      velocityRef.current *= FRICTION;

      const isAtLeft = el.scrollLeft <= 0 && velocityRef.current > 0;
      const isAtRight = el.scrollLeft >= el.scrollWidth - el.clientWidth && velocityRef.current < 0;

      if (Math.abs(velocityRef.current) < VELOCITY_THRESHOLD || isAtLeft || isAtRight) {
        animFrameRef.current = null;
        velocityRef.current = 0;
        return;
      }

      animFrameRef.current = requestAnimationFrame(step);
    };

    animFrameRef.current = requestAnimationFrame(step);
  }, [stopMomentum]);

  const updateDragMove = useCallback((clientX) => {
    if (!dragRef.current.isDown) return;
    const el = scrollerRef.current;
    if (!el) return;

    const now = performance.now();
    const dt = Math.max(1, now - dragRef.current.lastTime);
    const dx = clientX - dragRef.current.lastX;

    const instantVelocity = (dx / dt) * 16.6;
    velocityRef.current = 0.7 * instantVelocity + 0.3 * velocityRef.current;

    dragRef.current.lastX = clientX;
    dragRef.current.lastTime = now;

    const walk = (clientX - dragRef.current.startX) * 1.1;
    if (Math.abs(walk) > 4) {
      dragRef.current.moved = true;
      setIsDragging(true);
    }
    el.scrollLeft = dragRef.current.scrollLeft - walk;
  }, []);

  const endDrag = useCallback(() => {
    if (!dragRef.current.isDown) return;
    dragRef.current.isDown = false;
    dragRef.current.wasDrag = dragRef.current.moved;
    setIsDragging(false);

    const now = performance.now();
    const timeSinceLastMove = now - dragRef.current.lastTime;

    if (dragRef.current.moved && timeSinceLastMove < 90 && Math.abs(velocityRef.current) > 0.8) {
      startMomentum(velocityRef.current);
    }

    setTimeout(() => {
      dragRef.current.wasDrag = false;
    }, 100);
  }, [startMomentum]);

  // Clean up momentum on unmount
  useEffect(() => {
    return () => {
      stopMomentum();
    };
  }, [stopMomentum]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;

    const onWheel = (e) => {
      if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
        e.preventDefault();
        stopMomentum();
        const wheelPulse = -e.deltaY * 0.45;
        startMomentum(wheelPulse);
      }
    };

    el.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      el.removeEventListener("wheel", onWheel);
    };
  }, [startMomentum, stopMomentum]);

  const handleMouseDown = (event) => {
    if (event.button !== undefined && event.button !== 0) return;
    stopMomentum();
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = event.clientX;
    dragRef.current.lastX = event.clientX;
    dragRef.current.lastTime = performance.now();
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
    velocityRef.current = 0;

    const handleGlobalMouseMove = (e) => {
      updateDragMove(e.clientX);
    };

    const handleGlobalMouseUp = () => {
      globalThis.removeEventListener("mousemove", handleGlobalMouseMove);
      globalThis.removeEventListener("mouseup", handleGlobalMouseUp);
      endDrag();
    };

    globalThis.addEventListener("mousemove", handleGlobalMouseMove);
    globalThis.addEventListener("mouseup", handleGlobalMouseUp);
  };

  const handleTouchStart = (event) => {
    const touch = event.touches[0];
    if (!touch) return;
    stopMomentum();
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = touch.clientX;
    dragRef.current.lastX = touch.clientX;
    dragRef.current.lastTime = performance.now();
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
    velocityRef.current = 0;
  };

  const handleTouchMove = (event) => {
    const touch = event.touches[0];
    if (!touch) return;
    updateDragMove(touch.clientX);
  };

  const handleTouchEnd = () => {
    endDrag();
  };

  const handleKeyDown = (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      stopMomentum();
      const el = scrollerRef.current;
      if (!el) return;
      const scrollAmount = e.key === "ArrowLeft" ? -320 : 320;
      el.scrollBy({ left: scrollAmount, behavior: "smooth" });
    }
  };

  const handleClickCapture = (event) => {
    if (dragRef.current.wasDrag) {
      event.preventDefault();
      event.stopPropagation();
      dragRef.current.wasDrag = false;
    }
  };

  return {
    scrollerRef,
    isDragging,
    stopMomentum,
    dragHandlers: {
      onMouseDown: handleMouseDown,
      onTouchStart: handleTouchStart,
      onTouchMove: handleTouchMove,
      onTouchEnd: handleTouchEnd,
      onKeyDown: handleKeyDown,
      onClickCapture: handleClickCapture,
    },
  };
};

export default useDragScroll;
