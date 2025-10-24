"use client"

import { motion } from "framer-motion"
import { useInView } from "react-intersection-observer"
import { ReactNode } from "react"

interface SectionTransitionProps {
  children: ReactNode
  className?: string
  delay?: number
}

export function SectionTransition({
  children,
  className = "",
  delay = 0
}: SectionTransitionProps) {
  const [ref, inView] = useInView({
    threshold: 0.1,
    triggerOnce: true,
  })

  return (
    <motion.section
      ref={ref}
      initial={{ opacity: 0, y: 50 }}
      animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 50 }}
      transition={{
        duration: 0.8,
        delay,
        ease: [0.25, 0.46, 0.45, 0.94]
      }}
      className={className}
    >
      {children}
    </motion.section>
  )
}

export function SmoothTransition({
  children,
  className = ""
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.5 }}
      className={className}
    >
      {children}
    </motion.div>
  )
}