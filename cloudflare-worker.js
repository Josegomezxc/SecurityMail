/**
 * Cloudflare Email Worker — reenvía emails entrantes a Django.
 *
 * Despliegue:
 *   1. Ir a Cloudflare Dashboard → Email → Email Routing → Workers
 *   2. Crear Worker con este código
 *   3. Crear ruta: tu-dominio → este Worker
 *   4. Crear ruta catch-all: * → este Worker
 *
 * Rollback: cambiar MX de vuelta a Resend en Cloudflare Dashboard.
 *
 * Nota: Las imágenes y archivos grandes (>10MB) pueden exceder el límite
 * de Workers Free. Si ves errores, actualiza a Workers Paid ($5/mes).
 */

export default {
  async email(message, env, ctx) {
    const webhookUrl = 'https://app.dockershield.lat/webhook/inbound/cloudflare/';

    try {
      // Leer el email crudo (raw MIME)
      const rawEmail = await new Response(message.raw).text();

      // Enviar al webhook de Django
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'message/rfc822',
          'X-Cloudflare-Email': 'true',
        },
        body: rawEmail,
      });

      if (!response.ok) {
        console.error(`[email-worker] Django respondió ${response.status}: ${await response.text()}`);
      }
    } catch (err) {
      console.error(`[email-worker] Error reenviando email: ${err.message}`);
    }
  },
};
