"use client"

import { motion } from "framer-motion"
import { useInView } from "react-intersection-observer"

interface StaggerContainerProps {
  children: React.ReactNode
  staggerDelay?: number
  childDelay?: number
  className?: string
}

export function StaggerContainer({
  children,
  staggerDelay = 0.1,
  childDelay = 0,
  className = ""
}: StaggerContainerProps) {
  const [ref, inView] = useInView({
    triggerOnce: true,
    threshold: 0.1,
  })

  const containerVariants = {
    hidden: {},
    visible: {
      transition: {
        staggerChildren: staggerDelay,
        delayChildren: childDelay
      }
    }
  }

  return (
    <motion.div
      ref={ref}
      initial="hidden"
      animate={inView ? "visible" : "hidden"}
      variants={containerVariants}
      className={className}
    >
      {children}
    </motion.div>
  )
}

interface StaggerChildProps {
  children: React.ReactNode
  direction?: "up" | "down" | "left" | "right" | "fade"
  distance?: number
  duration?: number
  className?: string
}

export function StaggerChild({
  children,
  direction = "up",
  distance = 30,
  duration = 0.6,
  className = ""
}: StaggerChildProps) {
  const getVariants = () => {
    switch (direction) {
      case "up":
        return {
          hidden: { y: distance, opacity: 0 },
          visible: {
            y: 0,
            opacity: 1,
            transition: {
              duration,
              ease: [0.25, 0.46, 0.45, 0.94] as const
            }
          }
        }
      case "down":
        return {
          hidden: { y: -distance, opacity: 0 },
          visible: {
            y: 0,
            opacity: 1,
            transition: {
              duration,
              ease: [0.25, 0.46, 0.45, 0.94] as const
            }
          }
        }
      case "left":
        return {
          hidden: { x: distance, opacity: 0 },
          visible: {
            x: 0,
            opacity: 1,
            transition: {
              duration,
              ease: [0.25, 0.46, 0.45, 0.94] as const
            }
          }
        }
      case "right":
        return {
          hidden: { x: -distance, opacity: 0 },
          visible: {
            x: 0,
            opacity: 1,
            transition: {
              duration,
              ease: [0.25, 0.46, 0.45, 0.94] as const
            }
          }
        }
      case "fade":
        return {
          hidden: { opacity: 0 },
          visible: {
            opacity: 1,
            transition: {
              duration,
              ease: "easeOut" as const
            }
          }
        }
      default:
        return {
          hidden: { y: distance, opacity: 0 },
          visible: {
            y: 0,
            opacity: 1,
            transition: {
              duration,
              ease: [0.25, 0.46, 0.45, 0.94] as const
            }
          }
        }
    }
  }

  return (
    <motion.div variants={getVariants()} className={className}>
      {children}
    </motion.div>
  )
}