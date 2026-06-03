// src/pages/Tools.tsx
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { DnsTxtChecker } from '../components/DnsTxtChecker';
import { CertViewer } from '../components/CertViewer';

export default function Tools(): React.ReactElement {
  return (
    <Routes>
      <Route path="dns-txt" element={<DnsTxtChecker />} />
      <Route path="cert-viewer" element={<CertViewer />} />
      <Route path="*" element={<Navigate to="dns-txt" replace />} />
    </Routes>
  );
}
