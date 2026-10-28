import { useEffect, useRef } from 'react';

import styles from '@encryption/src/ui/components/layout/layout.module.css';

/**
 * The rear camera, decoding QR codes with jsQR until one is found. Used where a
 * person reads a code on someone else's screen: pairing a device, and the last
 * share of a council recovery. `onUnavailable` fires without a camera or
 * permission, so the caller falls back to typing the digits.
 */
export function QrScanner({ onDecode, onUnavailable, label }: { onDecode: (text: string) => void; onUnavailable: () => void; label: string }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let raf = 0;
    let cancelled = false;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    // The decoder is only needed while the camera runs: its own chunk.
    let decode: ((data: Uint8ClampedArray, width: number, height: number) => { data: string } | null) | null = null;

    const tick = () => {
      if (cancelled) return;
      const video = videoRef.current;

      if (video && ctx && video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const found = decode?.(img.data, img.width, img.height);

        if (found?.data) {
          onDecode(found.data);

          return; // stop the loop; the parent unmounts the scanner
        }
      }

      raf = requestAnimationFrame(tick);
    };

    (async () => {
      try {
        decode = (await import('jsqr')).default;
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        if (cancelled) {
          stream.getTracks().forEach((tr) => tr.stop());

          return;
        }
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }
        raf = requestAnimationFrame(tick);
      } catch {
        // No camera / permission denied — fall back to manual entry.
        onUnavailable();
      }
    })();

    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
      stream?.getTracks().forEach((tr) => tr.stop());
    };
  }, [onDecode, onUnavailable]);

  return <video ref={videoRef} muted playsInline className={styles.scanner} aria-label={label} />;
}
