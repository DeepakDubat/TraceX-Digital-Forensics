import React, { useState } from 'react';
import { GraphNode, GraphLink } from '../types';
import { Shield, RadioTower, KeyRound, TerminalSquare, Package, Info, X } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';

interface EvidenceGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
}

export const EvidenceGraph: React.FC<EvidenceGraphProps> = ({ nodes, links }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  if (!nodes || nodes.length === 0) {
    return (
      <div className="h-96 flex flex-col items-center justify-center border border-dashed border-app rounded-xl p-8 text-center text-app-muted bg-surface">
        <Info className="w-10 h-10 mb-2.5 text-app-muted" />
        <p className="font-semibold text-app-primary text-sm">No structural evidence nodes correlated yet.</p>
        <p className="text-xs text-app-secondary mt-1">Run static analysis to extract graph relationships.</p>
      </div>
    );
  }

  // Calculate layout coordinates in a circular/star distribution around central target node
  const width = 800;
  const height = 500;
  const centerX = width / 2;
  const centerY = height / 2;

  const rootNode = nodes.find((n) => n.type === 'apk' || n.type === 'exe') || nodes[0];
  const otherNodes = nodes.filter((n) => n.id !== rootNode.id);

  const radius = Math.min(width, height) * 0.38;
  const angleStep = (2 * Math.PI) / Math.max(otherNodes.length, 1);

  const nodePositions: Record<string, { x: number; y: number }> = {
    [rootNode.id]: { x: centerX, y: centerY },
  };

  otherNodes.forEach((node, idx) => {
    const angle = idx * angleStep;
    nodePositions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    };
  });

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'apk':
      case 'exe':
        return '#0284c7'; // Cyan / Sky Blue
      case 'package':
        return '#6366f1'; // Indigo
      case 'c2':
        return '#d97706'; // Amber
      case 'secret':
        return '#0284c7'; // Sky
      case 'reverse_shell':
      case 'persistence':
        return '#e11d48'; // Rose
      default:
        return '#64748b'; // Slate
    }
  };

  return (
    <div className="relative forensics-card rounded-xl overflow-hidden shadow-sm">
      {/* Graph Toolbar */}
      <div className="p-3.5 border-b border-app bg-surface flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-4 text-app-secondary font-medium">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-600 inline-block"></span> Target File
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-600 inline-block"></span> C2 Endpoint
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-600 inline-block"></span> Secret/Token
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-600 inline-block"></span> Threat Vector
          </span>
        </div>
        <span className="text-app-muted font-mono font-medium text-xs">{nodes.length} Nodes Correlated</span>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full h-[520px] flex items-center justify-center bg-slate-50/50 dark:bg-[#0c1017]">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full">
          {/* Draw Links */}
          {links.map((link, idx) => {
            const src = nodePositions[link.source];
            const dst = nodePositions[link.target];
            if (!src || !dst) return null;
            return (
              <g key={idx}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  className="stroke-slate-300 dark:stroke-slate-700"
                  strokeWidth="1.5"
                  strokeDasharray="4 2"
                />
              </g>
            );
          })}

          {/* Draw Nodes */}
          {nodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;
            const isSelected = selectedNode?.id === node.id;
            const color = getNodeColor(node.type);
            const isRoot = node.type === 'apk' || node.type === 'exe';
            const nodeRadius = isRoot ? 26 : 18;

            return (
              <g
                key={node.id}
                className="cursor-pointer transition-transform"
                onClick={() => setSelectedNode(node)}
              >
                {/* Glow ring if selected */}
                {isSelected && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={nodeRadius + 8}
                    fill="none"
                    stroke={color}
                    strokeWidth="2.5"
                    strokeDasharray="4 4"
                    className="animate-spin origin-center"
                  />
                )}

                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={nodeRadius}
                  className="fill-white dark:fill-[#151b26]"
                  stroke={color}
                  strokeWidth={isRoot ? '3.5' : '2.5'}
                />

                {/* Node Label Text */}
                <text
                  x={pos.x}
                  y={pos.y + nodeRadius + 14}
                  textAnchor="middle"
                  className="fill-slate-700 dark:fill-slate-200 pointer-events-none select-none font-mono text-[11px] font-semibold"
                >
                  {node.label.length > 20 ? `${node.label.slice(0, 18)}...` : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Detail Card Overlay */}
        {selectedNode && (
          <div className="absolute bottom-4 right-4 max-w-sm forensics-card rounded-xl p-4 shadow-2xl backdrop-blur text-xs z-20 border-cyan-500/50">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] uppercase text-cyan-700 dark:text-cyan-400 font-bold tracking-wider font-mono">
                Node Inspector [{selectedNode.type.toUpperCase()}]
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-app-muted hover:text-app-primary p-1 rounded-md transition-colors"
                aria-label="Close details"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <p className="text-app-primary font-bold break-all mb-1 font-mono">{selectedNode.label}</p>
            {selectedNode.severity && (
              <div className="my-1.5">
                <SeverityBadge severity={selectedNode.severity} size="sm" />
              </div>
            )}
            <p className="text-app-secondary text-xs mt-2 leading-relaxed">
              {selectedNode.details || 'No additional telemetry recorded for this node.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
