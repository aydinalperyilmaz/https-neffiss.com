/**
 * Supabase Edge Function: iyzico-callback
 * ─────────────────────────────────────────
 * İyzico 3DS tamamlandıktan sonra banka bu endpoint'e POST atar.
 * Ödemeyi doğrular → Supabase'de order günceller → Frontend'e yönlendirir.
 *
 * Deploy:
 *   supabase functions deploy iyzico-callback --no-verify-jwt
 *
 * Secrets (iyzico-init ile aynı, bir kez set edildi):
 *   IYZICO_API_KEY, IYZICO_SECRET_KEY, IYZICO_BASE_URL
 *   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY  ← Supabase otomatik inject eder
 *   FRONTEND_URL
 */

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createHmac } from "https://deno.land/std@0.177.0/node/crypto.ts";

function generateIyzicoAuthHeader(
  apiKey: string,
  secretKey: string,
  randomString: string,
  requestBody: string
): string {
  const hashStr = apiKey + randomString + secretKey + requestBody;
  const hash = createHmac("sha256", secretKey).update(hashStr).digest("base64");
  return "IYZWSv2 " + btoa(`apiKey:${apiKey}&randomKey:${randomString}&signature:${hash}`);
}

serve(async (req) => {
  const IYZICO_API_KEY = Deno.env.get("IYZICO_API_KEY") ?? "";
  const IYZICO_SECRET = Deno.env.get("IYZICO_SECRET_KEY") ?? "";
  const IYZICO_URL = Deno.env.get("IYZICO_BASE_URL") ?? "https://sandbox-api.iyzipay.com";
  const FRONTEND_URL = Deno.env.get("FRONTEND_URL") ?? "http://localhost:5500";
  const SB_URL = Deno.env.get("SUPABASE_URL") ?? "";
  const SB_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

  try {
    // İyzico POST olarak form-data gönderir
    const formData = await req.formData().catch(() => null);
    let paymentId = "";
    let conversationData = "";
    let conversationId = "";

    if (formData) {
      paymentId = formData.get("paymentId")?.toString() ?? "";
      conversationData = formData.get("conversationData")?.toString() ?? "";
      conversationId = formData.get("conversationId")?.toString() ?? "";
    } else {
      // JSON fallback
      const json = await req.json().catch(() => ({}));
      paymentId = json.paymentId ?? "";
      conversationData = json.conversationData ?? "";
      conversationId = json.conversationId ?? "";
    }

    if (!paymentId) {
      return Response.redirect(`${FRONTEND_URL}/?payment=fail&msg=Eksik+parametre`, 302);
    }

    // ── İyzico'ya ödemeyi onayla ──────────────────────────────────
    const reqBody = JSON.stringify({
      locale: "tr",
      conversationId,
      paymentId,
      conversationData,
    });

    const randomKey = Math.random().toString(36).substring(2, 15);
    const authHeader = generateIyzicoAuthHeader(IYZICO_API_KEY, IYZICO_SECRET, randomKey, reqBody);

    const iyziRes = await fetch(`${IYZICO_URL}/payment/3dsecure/auth`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authHeader,
        "x-iyzi-rnd": randomKey,
        "x-iyzi-client-version": "iyzipay-deno-1.0",
      },
      body: reqBody,
    });

    const result = await iyziRes.json();

    if (result.status !== "success") {
      const errMsg = encodeURIComponent(result.errorMessage || "Ödeme doğrulanamadı");
      // Sipariş payment_status = failed olarak işaretle
      if (SB_URL && SB_SERVICE_KEY && conversationId) {
        await fetch(`${SB_URL}/rest/v1/orders?id=eq.${conversationId}`, {
          method: "PATCH",
          headers: {
            apikey: SB_SERVICE_KEY,
            Authorization: `Bearer ${SB_SERVICE_KEY}`,
            "Content-Type": "application/json",
            Prefer: "return=minimal",
          },
          body: JSON.stringify({ payment_status: "failed" }),
        }).catch(() => {});
      }
      return Response.redirect(
        `${FRONTEND_URL}/?payment=fail&msg=${errMsg}&orderId=${conversationId}`,
        302
      );
    }

    // ── 2. ADIM: İyzico'dan ödeme detayını tekrar sorgula (double-check) ─
    // Sadece callback'e güvenmek yerine, ayrı bir API çağrısıyla doğrula
    const verifyBody = JSON.stringify({
      locale: "tr",
      conversationId: `verify-${conversationId}`,
      paymentId: result.paymentId,
    });
    const verifyRndKey = Math.random().toString(36).substring(2, 15);
    const verifyHashStr = IYZICO_API_KEY + verifyRndKey + IYZICO_SECRET + verifyBody;
    const verifyHash = createHmac("sha256", IYZICO_SECRET).update(verifyHashStr).digest("base64");
    const verifyAuth = "IYZWSv2 " + btoa(`apiKey:${IYZICO_API_KEY}&randomKey:${verifyRndKey}&signature:${verifyHash}`);

    let verifiedPaid = false;
    try {
      const verifyRes = await fetch(`${IYZICO_URL}/payment/detail`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: verifyAuth,
          "x-iyzi-rnd": verifyRndKey,
          "x-iyzi-client-version": "iyzipay-deno-1.0",
        },
        body: verifyBody,
      });
      const verifyResult = await verifyRes.json();
      // Ödeme başarılı ve tutarlar eşleşiyor mu?
      if (
        verifyResult.status === "success" &&
        verifyResult.paymentStatus === "SUCCESS" &&
        verifyResult.paymentId === result.paymentId
      ) {
        verifiedPaid = true;
      } else {
        console.error("İyzico double-check failed:", verifyResult.paymentStatus, verifyResult.errorMessage);
      }
    } catch (verifyErr) {
      console.error("İyzico verify error:", verifyErr);
      // Doğrulama yapılamazsa ilk sonuca güven (network hatası ihtimali)
      verifiedPaid = result.paymentStatus === "SUCCESS";
    }

    if (!verifiedPaid) {
      const errMsg = encodeURIComponent("Ödeme doğrulaması başarısız");
      if (SB_URL && SB_SERVICE_KEY && conversationId) {
        await fetch(`${SB_URL}/rest/v1/orders?id=eq.${conversationId}`, {
          method: "PATCH",
          headers: {
            apikey: SB_SERVICE_KEY,
            Authorization: `Bearer ${SB_SERVICE_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ payment_status: "failed" }),
        }).catch(() => {});
      }
      return Response.redirect(
        `${FRONTEND_URL}/?payment=fail&msg=${errMsg}&orderId=${conversationId}`,
        302
      );
    }

    // ── 3. ADIM: Supabase'de order'ı paid olarak güncelle ────────
    // Sadece İyzico double-check geçtikten sonra 'paid' yazıyoruz
    // paymentTransactionId'yi de kaydet (otomatik iade için gerekli)
    const txId = result.paymentItems?.[0]?.paymentTransactionId ?? null;
    if (SB_URL && SB_SERVICE_KEY && conversationId) {
      await fetch(`${SB_URL}/rest/v1/orders?id=eq.${conversationId}`, {
        method: "PATCH",
        headers: {
          apikey: SB_SERVICE_KEY,
          Authorization: `Bearer ${SB_SERVICE_KEY}`,
          "Content-Type": "application/json",
          Prefer: "return=minimal",
        },
        body: JSON.stringify({
          payment_status: "paid",
          status: "confirmed",
          iyzico_payment_id: result.paymentId,
          iyzico_payment_transaction_id: txId,
          status_history: [
            { status: "confirmed", at: new Date().toISOString(), note: `Online ödeme doğrulandı — İyzico ID: ${result.paymentId}` },
          ],
        }),
      });
    }

    // ── 4. ADIM: Başarı → Frontend'e yönlendir ───────────────────
    return Response.redirect(
      `${FRONTEND_URL}/?payment=success&orderId=${conversationId}&paymentId=${result.paymentId}`,
      302
    );
  } catch (err) {
    console.error("iyzico-callback error:", err);
    return Response.redirect(
      `${FRONTEND_URL}/?payment=fail&msg=${encodeURIComponent(String(err))}`,
      302
    );
  }
});
