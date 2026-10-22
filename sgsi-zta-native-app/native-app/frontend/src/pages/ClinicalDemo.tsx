import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  HeartPulse,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  FileText,
  Lock,
  ArrowRight,
} from 'lucide-react';
import { zeroTrustApi } from '../services/zeroTrustApi';
import { ApiError } from '../services/api';
import type {
  ClinicalRecord,
  EvaluateResponse,
  EvaluationContext,
  ReasonCode,
} from '../types/zeroTrust';
import { DecisionBadge } from '../components/DecisionBadge';
import { ReasonCodeBadge } from '../components/ReasonCodeBadge';
import { useAuth } from '../hooks/useAuth';

interface ClinicalErrorDetail {
  code?: ReasonCode;
  message?: string;
  decision_id?: string;
  policy_code?: string | null;
  context?: EvaluationContext | null;
}

export const ClinicalDemo: React.FC = () => {
  const { user } = useAuth();
  const [records, setRecords] = useState<ClinicalRecord[]>([]);
  const [loading, setLoading] = useState(true);

  // Selected record state & evaluation
  const [selectedRecord, setSelectedRecord] = useState<ClinicalRecord | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [evaluation, setEvaluation] = useState<EvaluateResponse | null>(null);

  useEffect(() => {
    let active = true;
    zeroTrustApi
      .getClinicalRecords()
      .then((data) => {
        if (active) setRecords(data);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const handleOpenRecord = async (rec: ClinicalRecord) => {
    setSelectedRecord(rec);
    setEvaluating(true);
    setEvaluation(null);

    try {
      // Real PEP: invoke GET /api/v1/clinical/{id}
      const fullRecord = await zeroTrustApi.getClinicalRecord(rec.demo_id);
      setSelectedRecord(fullRecord);
      setEvaluation({
        decision: 'ALLOW',
        reason_code: 'POLICY_ALLOW',
        policy_code: fullRecord.policy_code ?? null,
        evaluation_id: fullRecord.decision_id ?? 'No disponible',
        context: fullRecord.context ?? {
          mfa_verified: true,
          device_trust: 'TRUSTED',
          effective_risk_score: 0,
          effective_risk_level: 'LOW',
        },
      });
    } catch (err) {
      const errDetail =
        err instanceof ApiError &&
        typeof err.data === 'object' &&
        err.data !== null &&
        'detail' in err.data
          ? (err.data.detail as ClinicalErrorDetail)
          : null;
      const code = errDetail?.code ?? 'DEFAULT_DENY';
      const decisionId = errDetail?.decision_id ?? 'No disponible';
      const serverPolicy = errDetail?.policy_code ?? null;
      const serverContext = errDetail?.context ?? {
        mfa_verified: false,
        device_trust: 'UNTRUSTED',
        effective_risk_score: 0,
        effective_risk_level: 'LOW',
      };

      if (code === 'MFA_REQUIRED') {
        setEvaluation({
          decision: 'MFA_REQUIRED',
          reason_code: 'MFA_REQUIRED',
          policy_code: serverPolicy,
          evaluation_id: decisionId,
          context: serverContext,
        });
      } else {
        setEvaluation({
          decision: 'DENY',
          reason_code: code,
          policy_code: serverPolicy,
          evaluation_id: decisionId,
          context: serverContext,
        });
      }
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <HeartPulse className="text-rose-500" size={26} />
          Demostración Clínica — Evaluación de Acceso a Historias
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Validación en tiempo de ejecución del principio Zero Trust: el acceso a datos médicos
          sintéticos se autoriza de forma explícita por política.
        </p>
      </div>

      {/* Mandatory Academic Warning Banner */}
      <div className="rounded-xl border border-amber-600/70 bg-amber-950/40 p-4 text-amber-200 text-xs flex items-center gap-3 shadow-sm">
        <AlertTriangle size={22} className="shrink-0 text-amber-400" />
        <div>
          <strong className="block text-sm font-bold text-amber-300 uppercase tracking-wide">
            DATOS COMPLETAMENTE SINTÉTICOS · NO CONTIENE INFORMACIÓN REAL DE PACIENTES
          </strong>
          <span>
            Todos los expedientes, diagnósticos y nombres son ficticios y diseñados únicamente para
            validación académica del SGSI bajo ISO 27001 e HIPAA.
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-10 gap-6 items-start">
        {/* Synthetic Records List */}
        <div className="lg:col-span-4 space-y-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <FileText size={16} className="text-blue-400" />
                Historias Clínicas Disponibles
              </h2>
              <span className="text-xs text-slate-400">{records.length} expedientes</span>
            </div>
            <p className="text-xs text-slate-400">
              Seleccione un paciente sintético para validar en tiempo real la evaluación del PDP:
            </p>

            {loading ? (
              <div className="py-8 text-center text-xs text-slate-500">
                Cargando historias sintéticas...
              </div>
            ) : (
              <div className="space-y-3">
                {records.map((rec) => {
                  const isSelected = selectedRecord?.demo_id === rec.demo_id;
                  const isDenied = rec.status.includes('DENEGADO');
                  return (
                    <div
                      key={rec.id ?? rec.demo_id}
                      onClick={() => void handleOpenRecord(rec)}
                      className={`p-4 rounded-xl border transition cursor-pointer ${
                        isSelected
                          ? 'bg-blue-950/40 border-blue-500/80 shadow-md ring-1 ring-blue-500/50'
                          : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-800/30'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-cyan-400">
                            {rec.demo_id}
                          </span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              isDenied || rec.status === 'CRITICO'
                                ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                : rec.status === 'OBSERVACION'
                                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            }`}
                          >
                            {rec.status}
                          </span>
                        </div>
                        {rec.phi_classified && (
                          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-400 bg-rose-950/40 border border-rose-900/60 px-2 py-0.5 rounded">
                            <Lock size={11} /> PHI Sensible
                          </span>
                        )}
                      </div>

                      <div className="mt-2 text-sm font-semibold text-white">
                        {rec.patient_synthetic_name}
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">{rec.record_type}</div>

                      <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-800/40 pt-2">
                        <span>Dpto: {rec.department}</span>
                        <span className="text-blue-400 flex items-center gap-1 font-medium">
                          Evaluar Acceso <ArrowRight size={12} />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Access Evaluation & Record View */}
        <div className="lg:col-span-6">
          {!selectedRecord ? (
            <div className="rounded-xl border border-dashed border-slate-800 p-12 text-center text-slate-500">
              <FileText size={40} className="mx-auto text-slate-700 mb-3" />
              <p className="text-base font-semibold text-slate-400">Ningún Registro Seleccionado</p>
              <p className="text-xs text-slate-600 mt-1 max-w-sm mx-auto">
                Haga clic en una historia clínica a la izquierda para someter la solicitud de
                lectura al motor Zero Trust.
              </p>
            </div>
          ) : evaluating ? (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center text-slate-400 shadow-sm">
              <div className="inline-block w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3" />
              <p className="text-sm font-semibold text-white">
                Evaluando postura de seguridad en PEP...
              </p>
              <p className="text-xs text-slate-500 mt-1 font-mono">
                GET /api/v1/clinical/{selectedRecord.demo_id}
              </p>
            </div>
          ) : evaluation?.decision === 'ALLOW' ? (
            /* ALLOW SCREEN */
            <div className="rounded-xl border border-emerald-800/60 bg-slate-900/80 p-6 space-y-5 shadow-lg">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck size={20} className="text-emerald-400" />
                  <span className="text-xs uppercase font-bold text-emerald-400 tracking-wider">
                    Acceso Autorizado por Política
                  </span>
                </div>
                <DecisionBadge decision="ALLOW" size="md" />
              </div>

              <div>
                <span className="font-mono text-xs text-cyan-400 font-bold">
                  {selectedRecord.demo_id}
                </span>
                <h2 className="text-xl font-bold text-white mt-1">
                  {selectedRecord.patient_synthetic_name}
                </h2>
                <div className="flex flex-wrap gap-2 text-xs text-slate-400 mt-1">
                  <span>Rango edad: {selectedRecord.age_range} años</span>
                  <span>·</span>
                  <span>Departamento: {selectedRecord.department}</span>
                </div>
              </div>

              {selectedRecord.diagnosis_summary && (
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <span className="font-bold text-slate-300 block">
                    Diagnóstico y Hallazgo Clínico (Sintético):
                  </span>
                  <p className="text-slate-200 leading-relaxed text-sm">
                    {selectedRecord.diagnosis_summary}
                  </p>
                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-slate-400 text-[11px]">
                    <span>
                      Médico Tratante: {selectedRecord.attending_physician ?? 'No disponible'}
                    </span>
                    <span>
                      Actualizado:{' '}
                      {selectedRecord.last_updated
                        ? new Date(selectedRecord.last_updated).toLocaleDateString('es-PE')
                        : 'No disponible'}
                    </span>
                  </div>
                </div>
              )}

              <div className="text-[11px] text-slate-500 font-mono bg-slate-950/40 p-2.5 rounded border border-slate-800/60 flex items-center justify-between">
                <span>Política Aplicada: {evaluation.policy_code ?? 'No disponible'}</span>
                <span>Eval ID: {evaluation.evaluation_id}</span>
              </div>
            </div>
          ) : evaluation?.decision === 'DENY' ? (
            /* DENY SCREEN */
            <div className="rounded-xl border border-rose-800/80 bg-rose-950/30 p-8 text-center space-y-4 shadow-lg">
              <div className="w-14 h-14 rounded-full bg-rose-950 border border-rose-700/80 flex items-center justify-center mx-auto text-rose-400">
                <ShieldAlert size={30} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white tracking-wide">ACCESO DENEGADO</h2>
                <p className="text-xs text-rose-300/80 mt-1 max-w-sm mx-auto">
                  El motor Zero Trust ha bloqueado la visualización de este expediente médico según
                  las directivas de seguridad vigentes.
                </p>
              </div>

              <div className="flex justify-center">
                <ReasonCodeBadge code={evaluation.reason_code} />
              </div>

              <div className="p-4 rounded-lg bg-slate-950/90 border border-rose-900/50 text-left text-xs space-y-2 max-w-md mx-auto">
                <div className="flex justify-between text-slate-400">
                  <span>Usuario conectado:</span>
                  <span className="font-mono text-white">{user?.username ?? 'No disponible'}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Roles evaluados:</span>
                  <span className="font-mono text-white">
                    {user?.roles?.length ? user.roles.join(', ') : 'No disponible'}
                  </span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Recurso protegido:</span>
                  <span className="font-mono text-cyan-400">{selectedRecord.demo_id} (PHI)</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Decisión ID:</span>
                  <span className="font-mono text-slate-500 text-[10px]">
                    {evaluation.evaluation_id}
                  </span>
                </div>
              </div>
            </div>
          ) : evaluation?.decision === 'MFA_REQUIRED' ? (
            /* MFA REQUIRED SCREEN */
            <div className="rounded-xl border border-amber-700/80 bg-amber-950/30 p-8 text-center space-y-4 shadow-lg">
              <div className="w-14 h-14 rounded-full bg-amber-950 border border-amber-600/80 flex items-center justify-center mx-auto text-amber-400">
                <KeyRound size={30} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white tracking-wide">
                  SE REQUIERE AUTENTICACIÓN REFORZADA
                </h2>
                <p className="text-xs text-amber-200/80 mt-1 max-w-sm mx-auto">
                  El acceso a expedientes PHI sensibles exige validación de segundo factor (MFA)
                  activo según la directiva de seguridad del expediente (
                  {evaluation.policy_code ?? 'vigente'}).
                </p>
              </div>

              <div className="flex justify-center">
                <ReasonCodeBadge code="MFA_REQUIRED" />
              </div>

              <div className="pt-2">
                <Link
                  to="/mfa"
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow-md transition"
                >
                  <KeyRound size={15} />
                  Verificar MFA Ahora
                </Link>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};
