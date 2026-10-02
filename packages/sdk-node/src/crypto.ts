import { createHmac } from 'crypto';

export class BlindIndexer {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  public hashRoute(routePattern: string): string {
    return createHmac('sha256', this.secretKey)
      .update(routePattern.trim().toLowerCase())
      .digest('hex');
  }

  public signPayload(payload: string, timestamp: number): string {
    const dataToSign = `${timestamp}.${payload}`;
    return createHmac('sha256', this.secretKey)
      .update(dataToSign)
      .digest('hex');
  }
}