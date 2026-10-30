import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

export function NetworkTopology3D({ threatLevel = "LOW" }: { threatLevel?: "LOW" | "ELEVATED" | "CRITICAL" }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState(true);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // Reduced motion check
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Check WebGL availability
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
    } catch {
      setHasWebGL(false);
      return;
    }

    const W = container.clientWidth || 600;
    const H = container.clientHeight || 300;
    renderer.setSize(W, H);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, W / H, 0.1, 100);
    camera.position.set(0, 0, 7.5);

    // Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x22d3ee, 40, 20);
    pointLight.position.set(4, 3, 4);
    scene.add(pointLight);

    const threatColor = threatLevel === "CRITICAL" ? 0xef4444 : threatLevel === "ELEVATED" ? 0xf59e0b : 0x2563eb;
    const threatLight = new THREE.PointLight(threatColor, 35, 15);
    threatLight.position.set(-4, -2, 2);
    scene.add(threatLight);

    // Group
    const rootGroup = new THREE.Group();
    scene.add(rootGroup);

    // 1. Central Defense Knot
    const coreGeometry = new THREE.IcosahedronGeometry(1.6, 1);
    const coreMaterial = new THREE.MeshBasicMaterial({
      color: threatColor,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
    rootGroup.add(coreMesh);

    // Inner glowing sphere
    const innerGeo = new THREE.SphereGeometry(0.35, 16, 16);
    const innerMat = new THREE.MeshStandardMaterial({
      color: 0x93c5fd,
      emissive: 0x3b82f6,
      emissiveIntensity: 1.5,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    rootGroup.add(innerMesh);

    // 2. Network Node Topology (5 Agent Nodes in 3D orbit)
    const nodeGeo = new THREE.SphereGeometry(0.18, 16, 16);
    const agentNodes: THREE.Mesh[] = [];
    const nodeCount = 5;

    for (let i = 0; i < nodeCount; i++) {
      const angle = (i / nodeCount) * Math.PI * 2;
      const radius = 2.8;
      const nx = Math.cos(angle) * radius;
      const ny = Math.sin(angle * 0.8) * 1.2;
      const nz = Math.sin(angle) * radius;

      const nodeMat = new THREE.MeshStandardMaterial({
        color: i === 4 && threatLevel === "CRITICAL" ? 0xef4444 : 0x06b6d4,
        emissive: 0x0891b2,
        emissiveIntensity: 0.8,
      });
      const node = new THREE.Mesh(nodeGeo, nodeMat);
      node.position.set(nx, ny, nz);
      rootGroup.add(node);
      agentNodes.push(node);

      // Connecting line to core
      const lineMat = new THREE.LineBasicMaterial({
        color: 0x1e3a8a,
        transparent: true,
        opacity: 0.45,
      });
      const lineGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(nx, ny, nz),
      ]);
      const line = new THREE.Line(lineGeo, lineMat);
      rootGroup.add(line);
    }

    // 3. Orbit Particle Cloud
    const particleCount = 200;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      const r = 3.2 + Math.random() * 2.5;
      const theta = Math.random() * Math.PI * 2;
      const phi = (Math.random() - 0.5) * Math.PI;
      particlePositions[i * 3] = r * Math.cos(theta) * Math.cos(phi);
      particlePositions[i * 3 + 1] = r * Math.sin(phi);
      particlePositions[i * 3 + 2] = r * Math.sin(theta) * Math.cos(phi);
    }
    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute("position", new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      size: 0.045,
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.65,
      blending: THREE.AdditiveBlending,
    });
    const particles = new THREE.Points(particleGeo, particleMat);
    rootGroup.add(particles);

    // Mouse pointer interaction
    const pointer = { x: 0, y: 0 };
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
    };
    container.addEventListener("mousemove", onMouseMove, { passive: true });

    // Resize handler
    const onResize = () => {
      const nW = container.clientWidth;
      const nH = container.clientHeight;
      if (nW && nH) {
        camera.aspect = nW / nH;
        camera.updateProjectionMatrix();
        renderer.setSize(nW, nH);
      }
    };
    window.addEventListener("resize", onResize);

    // Animation Loop
    let animId = 0;
    const clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (prefersReduced) {
        renderer.render(scene, camera);
        return;
      }
      const delta = clock.getDelta();
      const elapsed = clock.getElapsedTime();

      // Rotate core & particles
      coreMesh.rotation.y += delta * 0.25;
      coreMesh.rotation.x = Math.sin(elapsed * 0.4) * 0.2;
      particles.rotation.y += delta * 0.08;

      // Gentle interactive tilt towards pointer
      rootGroup.rotation.y += (pointer.x * 0.4 - rootGroup.rotation.y) * 0.05;
      rootGroup.rotation.x += (-pointer.y * 0.3 - rootGroup.rotation.x) * 0.05;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
      container.removeEventListener("mousemove", onMouseMove);
      if (renderer.domElement && renderer.domElement.parentNode) {
        renderer.domElement.parentNode.removeChild(renderer.domElement);
      }
      renderer.dispose();
      coreGeometry.dispose();
      coreMaterial.dispose();
      innerGeo.dispose();
      innerMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
    };
  }, [threatLevel]);

  if (!hasWebGL) {
    return (
      <div
        style={{
          width: "100%",
          height: "100%",
          minHeight: 220,
          background: "radial-gradient(circle at center, #1e293b 0%, #0a0f1d 100%)",
          borderRadius: 8,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--muted)",
          fontSize: 12,
        }}
      >
        <span>WebGL unavailable · Fallback topology canvas active</span>
      </div>
    );
  }

  return (
    <div
      ref={mountRef}
      style={{
        width: "100%",
        height: "100%",
        minHeight: 240,
        position: "relative",
        overflow: "hidden",
        borderRadius: 8,
      }}
    />
  );
}

