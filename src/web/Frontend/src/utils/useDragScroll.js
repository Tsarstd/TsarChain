import { useState, useRef, useEffect } from "react";

export const useDragScroll = () => {
  const scrollerRef = useRef(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragRef = useRef({
    isDown: false,
    startX: 0,
    scrollLeft: 0,
    moved: false,
    wasDrag: false,
  });

  useEffect(() => {
    const handleGlobalMouseMove = (e) => {
      if (!dragRef.current.isDown) return;
      const el = scrollerRef.current;
      if (!el) return;

      const walk = (e.clientX - dragRef.current.startX) * 1.15;
      if (Math.abs(walk) > 5) {
        dragRef.current.moved = true;
        setIsDragging(true);
      }
      el.scrollLeft = dragRef.current.scrollLeft - walk;
    };

    const handleGlobalMouseUp = () => {
      if (!dragRef.current.isDown) return;
      dragRef.current.isDown = false;
      dragRef.current.wasDrag = dragRef.current.moved;
      setIsDragging(false);
      setTimeout(() => {
        dragRef.current.wasDrag = false;
      }, 100);
    };

    globalThis.addEventListener("mousemove", handleGlobalMouseMove);
    globalThis.addEventListener("mouseup", handleGlobalMouseUp);
    return () => {
      globalThis.removeEventListener("mousemove", handleGlobalMouseMove);
      globalThis.removeEventListener("mouseup", handleGlobalMouseUp);
    };
  }, []);

  const handleMouseDown = (event) => {
    if (event.button !== undefined && event.button !== 0) return;
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = event.clientX;
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
  };

  const handleTouchStart = (event) => {
    const touch = event.touches[0];
    if (!touch) return;
    const el = scrollerRef.current;
    if (!el) return;
    dragRef.current.isDown = true;
    dragRef.current.startX = touch.clientX;
    dragRef.current.scrollLeft = el.scrollLeft;
    dragRef.current.moved = false;
    dragRef.current.wasDrag = false;
  };

  const handleTouchMove = (event) => {
    if (!dragRef.current.isDown) return;
    const el = scrollerRef.current;
    if (!el) return;
    const touch = event.touches[0];
    if (!touch) return;
    const walk = (touch.clientX - dragRef.current.startX) * 1.15;
    if (Math.abs(walk) > 5) {
      dragRef.current.moved = true;
      setIsDragging(true);
    }
    el.scrollLeft = dragRef.current.scrollLeft - walk;
  };

  const handleTouchEnd = () => {
    dragRef.current.isDown = false;
    dragRef.current.wasDrag = dragRef.current.moved;
    setIsDragging(false);
    setTimeout(() => {
      dragRef.current.wasDrag = false;
    }, 100);
  };

  const handleKeyDown = (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const el = scrollerRef.current;
      if (!el) return;
      const scrollAmount = e.key === "ArrowLeft" ? -300 : 300;
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
