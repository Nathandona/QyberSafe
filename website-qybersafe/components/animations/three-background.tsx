"use client"

import { Canvas } from "@react-three/fiber"
import { Stars, Float, OrbitControls } from "@react-three/drei"
import { useTheme } from "next-themes"
import { useEffect, useRef } from "react"
import * as THREE from "three"

function AnimatedStars() {
  const { theme } = useTheme()
  const starsRef = useRef<THREE.Points>(null)

  useEffect(() => {
    if (starsRef.current) {
      const material = starsRef.current.material as THREE.PointsMaterial
      material.color = new THREE.Color(theme === "dark" ? 0xffffff : 0x1e293b)
      material.opacity = theme === "dark" ? 0.8 : 0.3
      material.needsUpdate = true
    }
  }, [theme])

  return (
    <Stars
      ref={starsRef}
      radius={100}
      depth={50}
      count={5000}
      factor={4}
      saturation={0}
      fade
      speed={1}
    />
  )
}

function FloatingOrbs() {
  const { theme } = useTheme()

  return (
    <>
      <Float
        speed={4}
        rotationIntensity={1}
        floatIntensity={2}
      >
        <mesh position={[-4, 2, -5]}>
          <sphereGeometry args={[0.5, 32, 32]} />
          <meshStandardMaterial
            color={theme === "dark" ? 0x8b5cf6 : 0x6366f1}
            emissive={theme === "dark" ? 0x8b5cf6 : 0x6366f1}
            emissiveIntensity={0.2}
            transparent
            opacity={0.6}
          />
        </mesh>
      </Float>

      <Float
        speed={3}
        rotationIntensity={0.5}
        floatIntensity={1.5}
      >
        <mesh position={[3, -2, -4]}>
          <sphereGeometry args={[0.3, 32, 32]} />
          <meshStandardMaterial
            color={theme === "dark" ? 0x06b6d4 : 0x0ea5e9}
            emissive={theme === "dark" ? 0x06b6d4 : 0x0ea5e9}
            emissiveIntensity={0.3}
            transparent
            opacity={0.5}
          />
        </mesh>
      </Float>

      <Float
        speed={5}
        rotationIntensity={1.5}
        floatIntensity={2.5}
      >
        <mesh position={[0, 3, -6]}>
          <sphereGeometry args={[0.4, 32, 32]} />
          <meshStandardMaterial
            color={theme === "dark" ? 0xf59e0b : 0xf59e0b}
            emissive={theme === "dark" ? 0xf59e0b : 0xf59e0b}
            emissiveIntensity={0.25}
            transparent
            opacity={0.4}
          />
        </mesh>
      </Float>
    </>
  )
}

export function ThreeBackground() {
  const { theme } = useTheme()

  return (
    <div className="fixed inset-0 z-0">
      <Canvas
        camera={{ position: [0, 0, 10], fov: 75 }}
        style={{ background: "transparent" }}
      >
        <ambientLight intensity={theme === "dark" ? 0.1 : 0.3} />
        <pointLight position={[10, 10, 10]} intensity={0.5} />
        <AnimatedStars />
        <FloatingOrbs />
        <OrbitControls
          enableZoom={false}
          enablePan={false}
          enableRotate={false}
          autoRotate
          autoRotateSpeed={0.5}
        />
      </Canvas>
    </div>
  )
}