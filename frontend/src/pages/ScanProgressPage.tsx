import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { PlayCircle, Terminal, CheckCircle, RefreshCw, Smartphone } from 'lucide-react';
import { api } from '../api/client';

interface LogEntry {
  timestamp: string;
  step: string;
  status: 'started' | 'success' | 'warning' | 'error';
  message: string;
  detail: string | null;
}

export default function ScanProgressPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [currentStep, setCurrentStep] = useState<string>('INIT');
  const [isWaitingForUser, setIsWaitingForUser] = useState(false);
  const [isFinalizing, setIsFinalizing] = useState(false);
  const [isCompleted, setIsCompleted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    if (!scanId || isCompleted) return;

    let eventSource: EventSource;

    const connectSSE = () => {
      const token = localStorage.getItem('token');
      eventSource = new EventSource(`http://127.0.0.1:8000/api/v1/scans/${scanId}/progress${token ? `?token=${token}` : ''}`);

      eventSource.onmessage = (event) => {
        try {
          let parsed = JSON.parse(event.data);
          if (typeof parsed === 'string') {
            parsed = JSON.parse(parsed);
          }
          const newLogs: LogEntry[] = Array.isArray(parsed) ? parsed : [parsed];
          
          if (newLogs && newLogs.length > 0) {
            setLogs((prev) => {
              // Simple deduplication based on exact match of message+timestamp
              const existing = new Set(prev.map(l => l.timestamp + l.message));
              const additions = newLogs.filter(l => !existing.has(l.timestamp + l.message));
              return [...prev, ...additions];
            });

            // Update state based on the latest log
            const latest = newLogs[newLogs.length - 1];
            if (latest && latest.step) {
              setCurrentStep(latest.step);

              if (latest.step === 'WAITING') {
                setIsWaitingForUser(true);
              }
              if (latest.step === 'DONE') {
                setIsCompleted(true);
                eventSource.close();
              }
            }
          }
        } catch (e) {
          console.error("Failed to parse SSE data:", e);
        }
      };

      eventSource.onerror = (err) => {
        console.error("SSE connection error:", err);
        // We do not close the eventSource immediately on error as it auto-reconnects,
        // but if it's consistently failing, we might want to poll the status instead.
      };
    };

    connectSSE();

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, [scanId, navigate, isCompleted]);

  const handleFinalize = async () => {
    setIsFinalizing(true);
    setError(null);
    try {
      await api.post(`/scans/${scanId}/finalize`);
      setIsWaitingForUser(false);
      // The SSE stream will automatically pick up the new events
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to finalize scan.");
      setIsFinalizing(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-green-500';
      case 'warning': return 'text-yellow-500';
      case 'error': return 'text-red-500';
      default: return 'text-cyan-500';
    }
  };

  const steps = [
    { id: 'INIT', label: 'Initialization' },
    { id: 'STATIC_ANALYSIS', label: 'Static Analysis' },
    { id: 'RESET', label: 'Device Prep' },
    { id: 'INSTALL', label: 'App Install' },
    { id: 'LAUNCH', label: 'App Launch' },
    { id: 'WAITING', label: 'Manual Testing' },
    { id: 'PULL', label: 'Data Extraction' },
    { id: 'ANALYSING', label: 'Vulnerability Scan' },
    { id: 'DONE', label: 'Report Generated' }
  ];

  const currentStepIndex = steps.findIndex(s => s.id === currentStep);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Scan Progress</h1>
        <p className="text-sm text-slate-500 mt-1">Scan ID: {scanId}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Timeline & Actions */}
        <div className="lg:col-span-1 space-y-6">
          {/* Stepper Component */}
          <div className="bg-white rounded-2xl p-6 shadow-sm border border-slate-100">
            <h3 className="text-lg font-bold text-slate-800 mb-6">Pipeline Status</h3>
            <div className="space-y-4">
              {steps.map((step, index) => {
                const isPast = index < currentStepIndex || isCompleted;
                const isCurrent = index === currentStepIndex && !isCompleted;
                
                return (
                  <div key={step.id} className="flex items-start">
                    <div className="flex flex-col items-center mr-4 mt-0.5">
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center border-2 
                        ${isPast ? 'bg-green-50 border-green-500 text-green-500' : 
                          isCurrent ? 'border-primary text-primary bg-primary/10' : 
                          'border-slate-200 text-slate-300'}`}
                      >
                        {isPast ? <CheckCircle className="w-4 h-4" /> : 
                         isCurrent ? <RefreshCw className="w-3 h-3 animate-spin" /> : 
                         <div className="w-2 h-2 rounded-full bg-slate-200" />}
                      </div>
                      {index !== steps.length - 1 && (
                        <div className={`w-0.5 h-6 mt-1 ${isPast ? 'bg-green-500' : 'bg-slate-200'}`}></div>
                      )}
                    </div>
                    <div className={`${isPast ? 'text-slate-700' : isCurrent ? 'text-primary font-medium' : 'text-slate-400'}`}>
                      {step.label}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* User Action Required Card */}
          {isWaitingForUser && !isCompleted && (
            <div className="bg-blue-50 border-2 border-primary rounded-2xl p-6 shadow-sm animate-pulse-border">
              <div className="flex items-center text-primary mb-4">
                <Smartphone className="w-6 h-6 mr-2" />
                <h3 className="text-lg font-bold">Action Required</h3>
              </div>
              <p className="text-slate-700 text-sm mb-6">
                Your app is now running on the emulator. Please interact with it manually (login, create notes, etc.) to generate data.
              </p>
              
              {error && (
                <div className="mb-4 text-red-500 text-sm font-medium bg-red-50 px-3 py-2 rounded">
                  {error}
                </div>
              )}

              <button 
                onClick={handleFinalize}
                disabled={isFinalizing}
                className="w-full bg-primary hover:bg-blue-600 text-white font-medium py-3 px-4 rounded-xl flex items-center justify-center transition-colors disabled:opacity-50"
              >
                {isFinalizing ? (
                  <><RefreshCw className="w-5 h-5 mr-2 animate-spin" /> Finalizing...</>
                ) : (
                  <><PlayCircle className="w-5 h-5 mr-2" /> I'm Done - Finalize Scan</>
                )}
              </button>
            </div>
          )}

          {/* Completed Card */}
          {isCompleted && (
            <div className="bg-green-50 border-2 border-green-500 rounded-2xl p-6 shadow-sm">
              <div className="flex items-center text-green-600 mb-4">
                <CheckCircle className="w-6 h-6 mr-2" />
                <h3 className="text-lg font-bold">Scan Complete</h3>
              </div>
              <p className="text-slate-700 text-sm mb-6">
                The analysis is finished and the final security report has been generated.
              </p>

              <button 
                onClick={() => navigate(`/scans/report/${scanId}`, { replace: true })}
                className="w-full bg-green-500 hover:bg-green-600 text-white font-medium py-3 px-4 rounded-xl flex items-center justify-center transition-colors"
              >
                View Full Report
              </button>
            </div>
          )}
        </div>

        {/* Right Column: Live Terminal logs */}
        <div className="lg:col-span-2">
          <div className="bg-[#1e293b] rounded-2xl shadow-md overflow-hidden flex flex-col h-[600px] border border-slate-700">
            <div className="bg-slate-900 px-4 py-3 border-b border-slate-700 flex items-center justify-between shrink-0">
              <div className="flex items-center text-slate-400">
                <Terminal className="w-5 h-5 mr-2" />
                <span className="font-mono text-sm font-medium">Live Execution Logs</span>
              </div>
              <div className="flex space-x-2">
                <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
              </div>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 font-mono text-xs sm:text-sm space-y-2">
              {logs.length === 0 ? (
                <div className="text-slate-500 animate-pulse">Waiting for logs...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="flex items-start">
                    <span className="text-slate-500 mr-3 shrink-0">
                      [{new Date(log.timestamp).toLocaleTimeString()}]
                    </span>
                    <div>
                      <span className={`${getStatusColor(log.status)}`}>
                        {log.message}
                      </span>
                      {log.detail && (
                        <div className="text-slate-400 mt-1 pl-2 border-l-2 border-slate-700 ml-1">
                          {log.detail}
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
