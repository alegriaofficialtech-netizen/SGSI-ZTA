import React from 'react';
import { REASON_CODE_COPY, type ReasonCode } from '../types/zeroTrust';

interface Props {
  code: ReasonCode;
  showExplanation?: boolean;
}

export const ReasonCodeBadge: React.FC<Props> = ({ code, showExplanation = true }) => {
  const explanation = REASON_CODE_COPY[code] ?? code;

  return (
    <div className="inline-flex flex-col text-left">
      <span className="font-mono text-xs font-semibold text-slate-300 tracking-wider">{code}</span>
      {showExplanation && (
        <span className="text-xs text-slate-400 mt-0.5 leading-snug">{explanation}</span>
      )}
    </div>
  );
};
