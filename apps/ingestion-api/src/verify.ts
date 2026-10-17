import { createHmac, timingSafeEqual } from 'node:crypto';

export interface VerificationResult {
  isValid: boolean;
  error?: string;
}

export function verifyAegisSignature(
  rawBody: string,
  timestampHeader: string | undefined,
  signatureHeader: string | undefined,
  clientSecret: string
): VerificationResult {
  if (!timestampHeader || !signatureHeader) {
    return { isValid: false, error: 'Faltan cabeceras de autenticacion' };
  }

  const timestamp = parseInt(timestampHeader, 10);
  const now = Date.now();

  // Descartar paquetes con desfase mayor a 5 minutos (mitigación de replay attacks)
  if (isNaN(timestamp) || Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return { isValid: false, error: 'Marca de tiempo fuera del rango permitido' };
  }

  // Recalcular la firma esperada con el mismo formato canónico que emite el SDK
  const dataToSign = `${timestamp}.${rawBody}`;
  const expectedSignature = createHmac('sha256', clientSecret)
    .update(dataToSign)
    .digest('hex');

  // Asegurar que ambas firmas tengan la misma longitud antes de timingSafeEqual
  const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
  const receivedBuffer = Buffer.from(signatureHeader.trim(), 'utf8');

  if (expectedBuffer.length !== receivedBuffer.length) {
    return { isValid: false, error: 'Firma criptografica invalida' };
  }

  if (!timingSafeEqual(expectedBuffer, receivedBuffer)) {
    return { isValid: false, error: 'Firma criptografica invalida' };
  }

  return { isValid: true };
}