import React from 'react';
import { Network, Info, ShieldAlert } from 'lucide-react';
import { InvestigationDetail } from '../types';
import { EvidenceGraph } from '../components/EvidenceGraph';

interface EvidenceGraphPageProps {
  detail: InvestigationDetail;
}

export const EvidenceGraphPage: React.FC<EvidenceGraphPageProps> = ({ detail }) => {
  const graphData = detail.graph_data || { nodes: [], links: [] };

  return (
    <div className="p-4 sm:p-6 md:p-8 space-y-6">
      {/* Header */}
      <div className="border-b border-app pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl md:text-2xl font-bold text-app-primary tracking-tight flex flex-wrap items-center gap-2.5">
            <span>IOC Correlation & Evidence Graph</span>
            <span className="text-xs bg-surface text-cyan-700 dark:text-cyan-400 border border-app px-2.5 py-1 rounded-md font-mono font-medium">
              {graphData.nodes.length} NODES / {graphData.links.length} RELATIONSHIPS
            </span>
          </h1>
          <p className="text-xs md:text-sm text-app-secondary mt-1">
            Interactive structural relationship graph mapping artifact components to C2 callbacks, tokens, and execution indicators.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs text-app-secondary bg-surface px-3 py-1.5 rounded-lg border border-app shadow-sm shrink-0">
          <Info className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
          <span>Click any node to inspect evidentiary context.</span>
        </div>
      </div>

      {/* Graph Visualizer */}
      <EvidenceGraph nodes={graphData.nodes} links={graphData.links} />

      {/* Explanatory Traceability Footer */}
      <div className="forensics-card p-4 rounded-xl text-xs text-app-secondary space-y-2 shadow-sm">
        <span className="text-app-primary font-bold text-xs uppercase flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
          <span>Forensic Traceability Standard</span>
        </span>
        <p className="leading-relaxed text-xs">
          Relationships represented above are strictly bound to verifiable byte-level offsets, string tables, and binary/manifest component bindings extracted during static parsing. Nodes are never linked speculatively without concrete decompiled evidence.
        </p>
      </div>
    </div>
  );
};
