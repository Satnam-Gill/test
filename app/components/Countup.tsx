'use client'
import React, { useEffect, useRef, useState, useCallback } from "react";

interface CountUpProps {
  start?: number;
  end: number;
}

const CountUp: React.FC<CountUpProps> = ({ start = 0, end }) => {
  const [value, setValue] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const counter = (end - start) / 200;
  
  const startRef = useRef(start); // Store the mutable value of 'start' using useRef

  const Count = useCallback(() => {
    let currentStart = startRef.current; // Access the current value of 'start' from the ref
    if (ref.current && ref.current.getBoundingClientRect().top < window.innerHeight) {
      const result: number = Math.ceil(currentStart + counter);
      if (result > end) return setValue(end);
      setValue(result);
      currentStart = result;  // Update the start value for the next iteration
      startRef.current = currentStart; // Update the value stored in the ref
    }
    setTimeout(Count, 70);
  }, [counter, end]); // 'startRef' does not need to be in the dependencies

  useEffect(() => {
    let isMounted = true;

    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        Count();
      }
    },);

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => {
      isMounted = false;
      observer.disconnect();
    };
  }, [Count]);

  return (
    <div className="" ref={ref}>
      <p className="text-4xl ">{value}+</p>
    </div>
  );
};

export default CountUp;
