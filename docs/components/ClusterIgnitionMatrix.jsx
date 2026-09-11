import React, { useState } from 'react';

const CLUSTER_NODES = [
  {
    id: 'vault',
    step: 'STEP 01',
    role: 'Central Database & Vault Server',
    subtitle: 'Cluster Brain & Ledger Hub',
    description:
      'Deploys the central SQLite WAL database, high-throughput gRPC ingestion engine (:50051), and Web SOC Dashboard (:8080) with cryptographic anti-tamper triggers.',
    pills: [
      { label: 'gRPC :50051', color: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20' },
      { label: 'Web SOC :8080', color: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20' },
      { label: 'SQLite WAL', color: 'border-purple-500/30 text-purple-400 bg-purple-950/20' }
    ],
    rawCommand:
      'curl -fsSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh \\\n  | sudo bash -s -- --role=controller',
    tokens: [
      { text: 'curl', type: 'cmd' },
      { text: ' -fsSL ', type: 'flag' },
      { text: 'https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh', type: 'url' },
      { text: ' \\\n  | ', type: 'punct' },
      { text: 'sudo', type: 'cmd' },
      { text: ' bash -s -- ', type: 'text' },
      { text: '--role=controller', type: 'param' }
    ]
  },
  {
    id: 'sensor',
    step: 'STEP 02',
    role: 'Edge Sensor Node',
    subtitle: 'Kernel-Native Ingress Inspector',
    description:
      'Attaches native eBPF/XDP packet inspection to the interface (eth0) and streams real-time threat telemetry directly to the central Vault server.',
    pills: [
      { label: 'eBPF/XDP Native', color: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20' },
      { label: 'Wire-Speed Drop', color: 'border-amber-500/30 text-amber-400 bg-amber-950/20' },
      { label: 'Auto-Replication', color: 'border-blue-500/30 text-blue-400 bg-blue-950/20' }
    ],
    rawCommand:
      'curl -fsSL https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh \\\n  | sudo bash -s -- --role=collector \\\n  --controller-ip=<SERVER_IP> --interface=eth0',
    tokens: [
      { text: 'curl', type: 'cmd' },
      { text: ' -fsSL ', type: 'flag' },
      { text: 'https://raw.githubusercontent.com/CoPdasten/copsec/main/scripts/install.sh', type: 'url' },
      { text: ' \\\n  | ', type: 'punct' },
      { text: 'sudo', type: 'cmd' },
      { text: ' bash -s -- ', type: 'text' },
      { text: '--role=collector', type: 'param' },
      { text: ' \\\n  ', type: 'punct' },
      { text: '--controller-ip=', type: 'flag' },
      { text: '<SERVER_IP>', type: 'placeholder' },
      { text: ' ', type: 'text' },
      { text: '--interface=eth0', type: 'param' }
    ]
  }
];

export default function ClusterIgnitionMatrix() {
  const [copiedId, setCopiedId] = useState(null);

  const handleCopy = async (id, rawText) => {
    try {
      await navigator.clipboard.writeText(rawText);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy to clipboard', err);
    }
  };

  const renderToken = (tok, idx) => {
    switch (tok.type) {
      case 'cmd':
        return <span key={idx} className="text-emerald-400 font-semibold">{tok.text}</span>;
      case 'flag':
        return <span key={idx} className="text-amber-400">{tok.text}</span>;
      case 'param':
        return <span key={idx} className="text-cyan-300">{tok.text}</span>;
      case 'url':
        return <span key={idx} className="text-sky-400/90 underline decoration-sky-500/30">{tok.text}</span>;
      case 'placeholder':
        return (
          <span key={idx} className="bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded border border-amber-500/40 font-bold">
            {tok.text}
          </span>
        );
      case 'punct':
        return <span key={idx} className="text-zinc-500 font-bold">{tok.text}</span>;
      default:
        return <span key={idx} className="text-zinc-300">{tok.text}</span>;
    }
  };

  return (
    <section className="w-full bg-[#050505] text-zinc-100 py-16 px-4 sm:px-6 lg:px-8 font-mono border-t border-b border-zinc-900">
      <div className="max-w-6xl mx-auto">
        {/* Section Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 text-xs tracking-wider uppercase mb-3">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Zero-Touch Deployment
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white mb-3">
            Cluster-Wide One-Line Ignition Matrix
          </h2>
          <p className="text-zinc-400 text-sm max-w-2xl mx-auto leading-relaxed font-sans">
            Bootstrap enterprise intrusion detection and zero-trust telemetry across a clean, decoupled 2-node architecture.
          </p>
        </div>

        {/* 2-Node Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
          {CLUSTER_NODES.map((node) => {
            const isCopied = copiedId === node.id;
            return (
              <div
                key={node.id}
                className="flex flex-col justify-between bg-[#0c0d10] border border-zinc-800/80 hover:border-zinc-700 rounded-lg p-6 transition-all duration-200 shadow-2xl relative overflow-hidden group"
              >
                {/* Top Accent Gradient */}
                <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-500/40 to-transparent group-hover:via-emerald-400 transition-all" />

                {/* Node Metadata */}
                <div>
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className="text-[11px] font-bold tracking-widest text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/20">
                      {node.step}
                    </span>
                    <span className="text-xs text-zinc-500 font-sans tracking-wide">
                      {node.subtitle}
                    </span>
                  </div>

                  <h3 className="text-lg font-bold text-white mb-2 tracking-wide">
                    {node.role}
                  </h3>

                  <p className="text-xs text-zinc-400 font-sans leading-relaxed mb-4 min-h-[48px]">
                    {node.description}
                  </p>

                  {/* Badges */}
                  <div className="flex flex-wrap gap-2 mb-6">
                    {node.pills.map((pill, pIdx) => (
                      <span
                        key={pIdx}
                        className={`text-[11px] px-2 py-0.5 rounded border font-mono ${pill.color}`}
                      >
                        {pill.label}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Terminal Code Snippet Container */}
                <div className="w-full bg-[#050608] border border-zinc-800 rounded-md overflow-hidden flex flex-col">
                  {/* Terminal Header */}
                  <div className="flex items-center justify-between px-3 py-2 bg-[#121318] border-b border-zinc-800 text-xs">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                      <span className="ml-2 text-[11px] text-zinc-400 font-mono">bash // root</span>
                    </div>

                    {/* Discrete Dedicated Copy Button */}
                    <button
                      type="button"
                      onClick={() => handleCopy(node.id, node.rawCommand)}
                      aria-label={`Copy ignition command for ${node.role}`}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-all duration-150 border ${
                        isCopied
                          ? 'bg-emerald-950 border-emerald-500 text-emerald-300'
                          : 'bg-zinc-800/80 hover:bg-zinc-700 border-zinc-700 text-zinc-200 hover:text-white'
                      }`}
                    >
                      {isCopied ? (
                        <>
                          <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                          </svg>
                          <span className="font-semibold text-emerald-400">COPIED</span>
                        </>
                      ) : (
                        <>
                          <svg className="w-3.5 h-3.5 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                          <span>COPY</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Code Body with Zero-Overflow Wrapping */}
                  <div className="p-3.5 bg-black/70 overflow-hidden">
                    <pre className="text-xs leading-relaxed font-mono whitespace-pre-wrap break-all select-all text-zinc-300">
                      {node.tokens.map((tok, idx) => renderToken(tok, idx))}
                    </pre>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
