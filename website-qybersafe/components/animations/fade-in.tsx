"use client"

import { motion } from "framer-motion"
import { useInView } from "react-intersection-observer"

interface FadeInProps {
  children: React.ReactNode
  delay?: number
  duration?: number
  from?: number
  className?: string
}

export function FadeIn({
  children,
  delay = 0,
  duration = 0.8,
  from = 0,
  className = ""
}: FadeInProps) {
  const [ref, inView] = useInView({
    triggerOnce: true,
    threshold: 0.1,
  })

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: from }}
      animate={inView ? { opacity: 1 } : { opacity: from }}
      transition={{
        duration,
        delay,
        ease: "easeOut"
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}