import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
const PEPPER = "bm-ops-v1:";
const INGEST_PEPPER = "bm-ingest-v1:";
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

async function sha(s: string) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const STAGES = ["ordered","purchased","shipped","received","airport","arrived","done","cancelled"];
const ORDER_FIELDS = ["client_name","client_phone","items","shop","shop_order_no","sale_tjs","purchase_eur","delivery_mode","address",
  "carrier","tracking_no","worker_id","flight_date","notes"];
const HIDDEN_SETTINGS = ["ingest_key_sha"];
const KNOWN_CARRIERS = ["DHL","Hermes","DPD","GLS","UPS","Amazon"];
const log = (user_id: string | null, action: string, order_id: string | null = null, detail: unknown = null) =>
  db.from("ops_log").insert({ user_id, action, order_id, detail });

/* ================= разбор писем ================= */
const squash = (s: string) => String(s ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
const digits = (s: string) => String(s ?? "").replace(/\D/g, "");
const cleanSubject = (s: string) => String(s ?? "").replace(/^\s*((fwd?|wg|aw|re|пересл|fw)\s*:\s*)+/i, "").trim();

function detectKind(subject: string, body: string): string | null {
  const s = subject.toLowerCase(), b = body.toLowerCase();
  const DELIV_S = /zugestellt|geliefert|delivered|ist da\b|ist angekommen|abholbereit|liegt .*bereit|in der packstation|in der filiale/;
  const SHIP_S = /versand|versendet|verschickt|unterwegs|auf dem weg|sendung|shipped|dispatched|tracking|paketankündigung|ankündigung|paket kommt|wird zugestellt|zustellung|on its way|on the way|out for delivery|delivery|lieferung/;
  const ORDER_S = /bestell|order|auftrag|kaufbestätigung|vielen dank für deinen einkauf|vielen dank für ihren einkauf|rechnung/;
  if (DELIV_S.test(s) && !/wird .*zugestellt|voraussichtlich|in kürze/.test(s)) return "delivered";
  if (SHIP_S.test(s)) return "shipped";
  if (ORDER_S.test(s)) return "order";
  if (/(wurde|ist|wurde erfolgreich) (heute )?(an .{0,40})?zugestellt|has been delivered|wurde geliefert/.test(b)) return "delivered";
  if (/wurde versandt|wurde versendet|ist unterwegs|ist auf dem weg|has shipped|sendungsnummer|trackingnummer/.test(b)) return "shipped";
  if (/bestellbestätigung|bestellnummer|order number|order confirmation/.test(b)) return "order";
  return null;
}

// рассылки, служебные письма и подтверждения фильтров — не заказы
function isNoise(from: string, subject: string): boolean {
  const f = from.toLowerCase(), s = subject.toLowerCase();
  if (/accounts\.google\.com|email\.apple\.com|mail\.ru\b.*(robot|notify)|noreply@id\.mail/.test(f)) return true;
  if (/сообщения, отправленные по адресу|weiterleitung|forwarding confirmation|подтверждение пересылки/.test(s)) return true;
  if (/newsletter|rabatt|gutschein|letzte chance|angebot|sale\b|deals?\b|aktion|gewinnspiel|\d+\s?%|black friday|vorteilsmail|bewerte|bewertung|umfrage/.test(s)
      && !/bestellung\s*(nr|#)?\s*\d|sendung|zugestellt|versandt|versendet/.test(s)) return true;
  if (/campaign\.|newsletter@|news@|marketing@/.test(f)) return true;
  return false;
}

function detectCarrier(from: string, text: string): string | null {
  const f = from.toLowerCase(), t = text.toLowerCase();
  const list: [RegExp, string][] = [[/dhl|deutsche post/, "DHL"], [/hermes/, "Hermes"], [/\bdpd\b|dpd\./, "DPD"],
    [/\bgls\b|gls-group|gls-pakete/, "GLS"], [/\bups\b|ups\.com/, "UPS"], [/amazon logistics|track\.amazon/, "Amazon"]];
  for (const [re, n] of list) if (re.test(f)) return n;
  for (const [re, n] of list) if (re.test(t)) return n;
  return null;
}

function detectTracking(text: string, carrier: string | null): string | null {
  const T = text.replace(/ /g, " ");
  const url = T.match(/(?:piececode|idc|tracknum|trackingnumber|tracking_number|match|parcelnumber|sendungsnummer)=([A-Z0-9]{8,35})/i)
    || T.match(/(?:\/parcel\/|\/tracking\/|sendungsinformation#)([A-Z0-9]{8,35})/i);
  if (url) return url[1].toUpperCase();
  const kw = T.match(/(?:sendungsnummer|sendungs-?nr\.?|trackingnummer|tracking-?nummer|tracking[- ]?id|tracking number|paketnummer|paket-?nr\.?|sendungsverfolgungsnummer)\s*[:#]?\s*(\d{2,6}(?: \d{2,6}){2,7}\b|[A-Z0-9]{8,35})/i);
  if (kw) { const n = kw[1].replace(/\s+/g, ""); if (/\d{6,}/.test(n) && n.length <= 35) return n.toUpperCase(); }
  const U = T.toUpperCase();
  const ups = U.match(/\b1Z[0-9A-Z]{16}\b/); if (ups) return ups[0];
  const dhl = U.match(/\b(00340\d{15,17}|JJD\d{10,24}|JVGL\d{10,20})\b/); if (dhl) return dhl[1];
  if (carrier === "Hermes") { const h = U.match(/\b(H\d{19}|\d{14})\b/); if (h) return h[1]; }
  if (carrier === "DPD") { const h = U.match(/\b(\d{14})\b/); if (h) return h[1]; }
  if (carrier === "GLS") { const h = U.match(/\b(\d{11,12})\b/); if (h) return h[1]; }
  if (carrier === "DHL") { const h = U.match(/\b(\d{12}|\d{20})\b/); if (h) return h[1]; }
  return null;
}
// один и тот же трек: точное совпадение или один номер — начало другого (у GLS бывает без контрольной цифры)
function sameTracking(a: string | null, b: string | null): boolean {
  const x = squash(a ?? ""), y = squash(b ?? "");
  if (x.length < 8 || y.length < 8) return false;
  if (x === y) return true;
  const [s, l] = x.length < y.length ? [x, y] : [y, x];
  return s.length >= 10 && l.length - s.length <= 2 && l.startsWith(s);
}

function parseEur(s: string): number | null {
  let x = s.replace(/\s/g, "");
  if (x.includes(",") && x.includes(".")) x = x.lastIndexOf(",") > x.lastIndexOf(".") ? x.replace(/\./g, "").replace(",", ".") : x.replace(/,/g, "");
  else x = x.replace(",", ".");
  const n = Number(x);
  return isFinite(n) && n > 0 && n < 100000 ? Math.round(n * 100) / 100 : null;
}
function detectAmount(text: string): number | null {
  const re = /(gesamtsumme|gesamtbetrag|endbetrag|summe|gesamt|total|zu zahlen|betrag)[^0-9\n]{0,40}?(?:€|eur)?\s*([0-9]{1,3}(?:[.\s][0-9]{3})*[.,][0-9]{2}|[0-9]+[.,][0-9]{2})/gi;
  let m, best: number | null = null;
  while ((m = re.exec(text))) { const v = parseEur(m[2]); if (v != null) { best = v; if (/gesamt|endbetrag|total|zu zahlen/i.test(m[1])) return v; } }
  return best;
}

function detectShopOrderNo(subject: string, body: string, tracking: string | null): string | null {
  const re = /(?:bestellnummer|bestell-?nr\.?|bestellungsnummer|auftragsnummer|auftrags-?nr\.?|order\s*(?:number|no\.?|nr\.?|id|#)|order\s*:|bestellung\s*(?:nr\.?|#)?|ordernummer)\s*[:#.]?\s*([A-Z0-9][A-Z0-9-]{3,29})/gi;
  for (const txt of [subject, body]) {
    for (const m of txt.matchAll(re)) {
      const n = m[1].replace(/-+$/, "");
      if ((n.match(/\d/g) ?? []).length >= 3 && !sameTracking(n, tracking) && squash(n) !== squash(tracking ?? "")) return n.toUpperCase();
    }
  }
  return null;
}
// совпадает ли № заказа магазина с текстом письма (с учётом «Nr.», дефисов, префиксов вроде ON…)
function shopNoIn(no: string | null, sq: string): boolean {
  const k = squash(no ?? ""), dg = digits(no ?? "");
  return (k.length >= 5 && sq.includes(k)) || (dg.length >= 7 && sq.includes(dg));
}
const sameShopNo = (a: string | null, b: string | null) => {
  const x = squash(a ?? ""), y = squash(b ?? ""), dx = digits(a ?? ""), dy = digits(b ?? "");
  return (x.length >= 4 && x === y) || (dx.length >= 7 && dx === dy);
};

/* --- магазин: по отправителю, домену и названию в теме письма службы доставки --- */
const GENERIC = new Set(["team","customer","service","services","kundenservice","de","com","net","shop","store","online","gmbh","ag","bv","b","v",
  "germany","deutschland","mail","email","news","notify","reply","info","communication","noreply","no","order","orders","kontakt","contact",
  "campaign","the","und","and","official","eu","www","co","uk","support","versand","paket","pakete","sendung","dein","deine","ihre","ihr","community"]);
const tokens = (s: string) => String(s ?? "").toLowerCase().split(/[^a-z0-9äöüß]+/).filter((t) => t && !GENERIC.has(t));
function senderDomain(from: string): string | null {
  const host = (from.match(/@([a-z0-9.-]+)/i)?.[1] ?? "").toLowerCase();
  const p = host.split(".").filter(Boolean);
  return p.length >= 2 ? p.slice(-2).join(".") : null;
}
function shopTokensOfMail(from: string, subject: string, isCarrier: boolean): string[] {
  if (isCarrier) {
    const m = subject.match(/(?:ihre|deine|dein|your)\s+(.{2,60}?)\s+(?:sendung|paket|lieferung|shipment|parcel)/i);
    return m ? tokens(m[1]) : [];
  }
  const name = from.replace(/<.*>/, "").replace(/["']/g, "");
  const host = (from.match(/@([a-z0-9.-]+)/i)?.[1] ?? "").toLowerCase().split(".");
  const label = host.length >= 2 ? host[host.length - 2] : "";
  return [...new Set([...tokens(/@/.test(name) ? "" : name), ...tokens(label)])];
}
function shopTokensOfOrder(o: Order): string[] {
  const dom = (o.shop_domain ?? "").split(".")[0];
  return [...new Set([...tokens(o.shop ?? ""), ...tokens(dom)])];
}
function tokensMatch(a: string[], b: string[]): boolean {
  for (const x of a) for (const y of b) {
    if (x === y) return true;
    if (x.length >= 4 && y.length >= 4 && (x.includes(y) || y.includes(x))) return true;
  }
  return false;
}
function detectShop(from: string): string | null {
  const name = from.replace(/<.*>/, "").replace(/["']/g, "").trim();
  const dom = (from.match(/@([a-z0-9.-]+)/i)?.[1] ?? "").toLowerCase().split(".").slice(-2, -1)[0] ?? "";
  const n = name && !/@/.test(name) ? name : dom;
  return n ? n.slice(0, 60) : null;
}

/* --- товары из письма-подтверждения --- */
function detectItems(text: string): string | null {
  const t = text.replace(/\r/g, "").replace(/\[image:\s*([^\]]*)\]/g, (_, a) => "[image: " + a.replace(/\s*\n\s*/g, " ") + "]");
  const lines = t.split("\n").map((l) => l.replace(/<https?:[^>]*>/g, "").replace(/\(\s*https?:[^)]*\)/g, "").replace(/\*/g, "").trim());
  const out: { n: string; q: number; sz: string }[] = [];
  const bad = /^(image|logo|facebook|instagram|youtube|tiktok|pinterest|app store|google play|sephora unlimited|swarovski|reserved|on|flaconi|dm)$/i;
  let prev = -1;
  for (let i = 0; i < lines.length; i++) {
    const q = lines[i].match(/^(?:anzahl|menge|qty|quantity|stückzahl)\s*:?\s*(\d{1,3})\b/i);
    if (q) {
      let name = "", size = "";
      for (let j = i - 1; j > prev && j >= i - 25; j--) {
        const l = lines[j];
        if (!size) { const g = l.match(/^(?:größe|groesse|size|grösse)\s*:\s*(.{1,30})$/i); if (g) size = g[1].trim(); }
        const im = l.match(/\[image:\s*([^\]]{3,160})\]/i);
        if (im && !bad.test(im[1].trim())) { name = im[1].trim(); break; }
      }
      if (!name) for (let j = i - 1; j > prev && j >= i - 8; j--) {
        const l = lines[j];
        if (l.length >= 4 && l.length <= 120 && /[a-zäöü]{3}/i.test(l) && !/:|eur|€|^\d|^\[image/i.test(l) && !/^[A-Z0-9-]{5,}$/.test(l)) { name = l; break; }
      }
      if (name) out.push({ n: name.replace(/,\s.*$/, "").slice(0, 80), q: +q[1], sz: size });
      prev = i;
      continue;
    }
    const x = lines[i].match(/^(\d{1,3})\s*[x×]\s+(.{3,80}?)\s*(?:=|€|\d+[.,]\d{2}|$)/i);
    if (x && !/^\d/.test(x[2])) { out.push({ n: x[2].trim(), q: +x[1], sz: "" }); continue; }
    const v = lines[i].match(/^-\s*(.{2,60}?)\s*[×x]\s*(\d{1,3})$/);
    if (v) { const nm = lines.slice(0, i).reverse().find((l) => l.length >= 3 && !/^-+$/.test(l)) ?? ""; out.push({ n: `${nm} — ${v[1]}`, q: +v[2], sz: "" }); }
  }
  if (!out.length) return null;
  if (out.every((x) => /apothekenartikel/i.test(x.n)))
    return `Аптечные товары: ${out.length} поз., ${out.reduce((a, x) => a + x.q, 0)} шт.`;
  // одинаковые позиции — сводим
  const agg = new Map<string, { n: string; q: number; sz: string }>();
  for (const x of out) { const k = (x.n + "|" + x.sz).toLowerCase(); const c = agg.get(k); if (c) c.q += x.q; else agg.set(k, { ...x }); }
  const list = [...agg.values()].map((x) => `${x.n} ×${x.q}${x.sz ? `, разм. ${x.sz}` : ""}`);
  return list.join("; ").slice(0, 600);
}

type Order = { id: string; num: number; stage: string; shop_order_no: string | null; tracking_no: string | null;
  carrier: string | null; purchase_eur: number | null; parcel_delivered_at: string | null; shop: string | null;
  shop_domain: string | null; auto_created: boolean; items: string | null; client_name: string | null; created_at: string };
const ORDER_COLS = "id,num,stage,shop_order_no,tracking_no,carrier,purchase_eur,parcel_delivered_at,shop,shop_domain,auto_created,items,client_name,created_at";

function findOrders(orders: Order[], mail: { subject: string; body: string; tracking_no: string | null }): Order[] {
  const sq = squash(mail.subject + " " + mail.body);
  const hit = new Map<string, Order>();
  for (const o of orders) {
    if (shopNoIn(o.shop_order_no, sq)) hit.set(o.id, o);
    const t = squash(o.tracking_no ?? "");
    if (t.length >= 8 && (sq.includes(t) || sameTracking(mail.tracking_no, o.tracking_no))) hit.set(o.id, o);
  }
  return [...hit.values()];
}

async function applyMail(o: Order, m: any, user_id: string | null) {
  const upd: Record<string, unknown> = {};
  const goodCarrier = o.carrier && KNOWN_CARRIERS.some((c) => c.toLowerCase() === o.carrier!.toLowerCase());
  if (m.tracking_no && !o.tracking_no) { upd.tracking_no = m.tracking_no; if (m.carrier && !goodCarrier) upd.carrier = m.carrier; }
  else if (m.carrier && !goodCarrier && (o.tracking_no || m.tracking_no) && (!m.tracking_no || sameTracking(m.tracking_no, o.tracking_no))) upd.carrier = m.carrier;
  // у GLS бывает короткая и полная форма трека — оставляем полную
  if (m.tracking_no && o.tracking_no && sameTracking(m.tracking_no, o.tracking_no) && squash(m.tracking_no).length > squash(o.tracking_no).length)
    upd.tracking_no = m.tracking_no;
  if (m.kind === "order" && o.purchase_eur == null && m.amount_eur) upd.purchase_eur = m.amount_eur;
  if (m.items_text && o.auto_created) {
    // товар заменяем, только если там ещё тема письма / пусто / наша прошлая автоподстановка
    const { data: subs } = await db.from("ops_mail").select("subject,items_text").eq("order_id", o.id);
    const autoVals = new Set([...(subs ?? []).flatMap((x) => [x.subject, x.items_text]), m.subject, "Заказ из письма"].filter(Boolean).map((s) => String(s).slice(0, 200)));
    if (!o.items || autoVals.has(String(o.items).slice(0, 200)) || autoVals.has(o.items)) upd.items = m.items_text;
  }
  if (!o.shop_domain && m.shop_domain) upd.shop_domain = m.shop_domain;
  let stage = o.stage;
  if (m.kind === "order" && stage === "ordered") stage = "purchased";
  if ((m.kind === "shipped" || m.kind === "delivered" || upd.tracking_no) && ["ordered","purchased"].includes(stage)) stage = "shipped";
  if (m.kind === "delivered" && !o.parcel_delivered_at) upd.parcel_delivered_at = m.received_at || new Date().toISOString();
  if (stage !== o.stage) { upd.stage = stage; upd.stage_at = new Date().toISOString(); }
  if (Object.keys(upd).length) {
    const { error } = await db.from("ops_orders").update(upd).eq("id", o.id);
    if (error) throw error;
  }
  await db.from("ops_mail").update({ status: "matched", order_id: o.id }).eq("id", m.id);
  await log(user_id, user_id ? "mail_link" : "mail_auto", o.id, { mail_id: m.id, ...upd });
  return upd;
}

async function createFromMail(m: any, shopNo: string, shop: string | null): Promise<Order> {
  const { data, error } = await db.from("ops_orders").insert({
    client_name: null, items: m.items_text || (m.subject || "Заказ из письма").slice(0, 200), shop, shop_order_no: shopNo,
    shop_domain: m.shop_domain, sale_tjs: 0, stage: "ordered", auto_created: true, notes: "Создан автоматически из письма магазина",
  }).select(ORDER_COLS).single();
  if (error) throw error;
  await log(null, "mail_create_order", data.id, { mail_id: m.id, shop_order_no: shopNo });
  return data as Order;
}

async function activeOrders(): Promise<Order[]> {
  const { data, error } = await db.from("ops_orders").select(ORDER_COLS).not("stage", "in", "(done,cancelled)").is("merged_into", null).limit(2000);
  if (error) throw error;
  return (data ?? []) as Order[];
}
async function findByShopNo(no: string): Promise<Order | null> {
  const dg = digits(no);
  const { data } = await db.from("ops_orders").select(ORDER_COLS).not("shop_order_no", "is", null).is("merged_into", null)
    .ilike("shop_order_no", `%${dg.length >= 7 ? dg : squash(no).slice(-6)}%`).limit(50);
  return ((data ?? []) as Order[]).find((o) => sameShopNo(o.shop_order_no, no)) ?? null;
}

/* одно письмо: дубль? шум? к какому заказу? */
const withDomain = (m: any) => ({ ...m, shop_domain: detectCarrier(m.from_addr ?? "", "") ? null : senderDomain(m.from_addr ?? "") });

async function processMail(m0: any, orders: Order[]): Promise<{ status: string; order?: number }> {
  const m = withDomain(m0);
  const fromCarrier = !!detectCarrier(m.from_addr, "");
  if (m.status === "ignored") return { status: "ignored" };
  // дубль: такое же письмо (тот же отправитель, тема, текст) уже было за 21 день
  const since = new Date(new Date(m.received_at || Date.now()).getTime() - 21 * 864e5).toISOString();
  const { data: twin } = await db.from("ops_mail").select("id,order_id,status").eq("content_hash", m.content_hash).neq("id", m.id)
    .in("status", ["matched","unmatched"]).gte("received_at", since).order("received_at").limit(1);
  if (twin?.length) {
    await db.from("ops_mail").update({ status: "duplicate", order_id: twin[0].order_id }).eq("id", m.id);
    return { status: "duplicate" };
  }
  const hits = findOrders(orders, { subject: m.subject, body: m.body, tracking_no: m.tracking_no });
  if (hits.length === 1) { await applyMail(hits[0], m, null); const o = hits[0]; return { status: "matched", order: o.num }; }
  if (hits.length > 1) return { status: "ambiguous" };

  const shopNo = detectShopOrderNo(m.subject, m.body, m.tracking_no);
  const shopToks = shopTokensOfMail(m.from_addr, m.subject, fromCarrier);
  const sameShop = (o: Order) => tokensMatch(shopToks, shopTokensOfOrder(o)) || (!!m.shop_domain && o.shop_domain === m.shop_domain);

  if (!fromCarrier && shopNo) {
    // уже есть заказ с этим номером (в т.ч. выданный/отменённый) — не создаём второй
    const ex = await findByShopNo(shopNo);
    if (ex) { await applyMail(ex, m, null); return { status: "matched", order: ex.num }; }
    if (m.kind === "order" || m.kind === "shipped") {
      // заказ, внесённый вручную без № магазина, того же магазина за последние 3 недели
      const recent = Date.now() - 21 * 864e5;
      const manual = orders.filter((o) => !o.auto_created && !o.shop_order_no && sameShop(o) && new Date(o.created_at).getTime() > recent);
      if (manual.length === 1) {
        await db.from("ops_orders").update({ shop_order_no: shopNo }).eq("id", manual[0].id);
        await applyMail({ ...manual[0], shop_order_no: shopNo }, m, null);
        return { status: "matched", order: manual[0].num };
      }
      if (manual.length > 1) return { status: "unmatched" };
      try {
        const o = await createFromMail(m, shopNo, detectShop(m.from_addr));
        await applyMail(o, m, null);
        return { status: "created", order: o.num };
      } catch (e) {
        // параллельная вставка того же номера — берём существующий
        const ex2 = await findByShopNo(shopNo);
        if (ex2) { await applyMail(ex2, m, null); return { status: "matched", order: ex2.num }; }
        throw e;
      }
    }
  }
  // нет номера: письмо службы доставки или магазина — ищем единственный подходящий заказ этого магазина
  if (shopToks.length && (m.kind === "shipped" || m.kind === "delivered" || (!fromCarrier && m.kind))) {
    let cand = orders.filter((o) => ["ordered","purchased","shipped"].includes(o.stage) && sameShop(o));
    if (m.tracking_no) cand = cand.filter((o) => !o.tracking_no);
    if (cand.length === 1) { await applyMail(cand[0], m, null); return { status: "matched", order: cand[0].num }; }
  }
  return { status: m.status };
}

async function ingest(body: any) {
  const { data: k } = await db.from("ops_settings").select("value").eq("key", "ingest_key_sha").maybeSingle();
  if (!k?.value || (await sha(INGEST_PEPPER + String(body.key ?? ""))) !== k.value) return json({ error: "bad key" }, 401);
  const mails = (Array.isArray(body.mails) ? body.mails : []).slice(0, 50);
  if (!mails.length) return json({ ok: true, results: [] });
  const ids = mails.map((m: any) => String(m.gmail_id));
  const { data: seen } = await db.from("ops_mail").select("gmail_id").in("gmail_id", ids);
  const seenSet = new Set((seen ?? []).map((x) => x.gmail_id));
  mails.sort((a: any, b: any) => String(a.date ?? "").localeCompare(String(b.date ?? "")));
  let orders = await activeOrders();
  const results: unknown[] = [];
  for (const raw of mails) {
    const gid = String(raw.gmail_id);
    if (seenSet.has(gid)) { results.push({ gmail_id: gid, status: "seen" }); continue; }
    seenSet.add(gid);
    const row = await parseMail(raw);
    const { data: m, error } = await db.from("ops_mail").insert({ gmail_id: gid, ...row }).select().single();
    if (error) { if (String(error.message).includes("duplicate")) { results.push({ gmail_id: gid, status: "seen" }); continue; } throw error; }
    const r = await processMail(m, orders);
    if (r.status === "matched" || r.status === "created") orders = await activeOrders();
    results.push({ gmail_id: gid, ...r, kind: m.kind, tracking_no: m.tracking_no });
  }
  return json({ ok: true, results });
}

async function parseMail(raw: any) {
  const subject = cleanSubject(String(raw.subject ?? "")).slice(0, 500), from = String(raw.from ?? raw.from_addr ?? "").slice(0, 300);
  const text = String(raw.body ?? "").slice(0, 20000);
  const kind = detectKind(subject, text);
  const carrier = detectCarrier(from, subject + "\n" + text);
  const tracking_no = detectTracking(subject + "\n" + text, carrier);
  const amount_eur = kind === "order" ? detectAmount(text) : null;
  const items_text = !detectCarrier(from, "") ? detectItems(text) : null;
  const fromEmail = (from.match(/<([^>]+)>/)?.[1] ?? from).toLowerCase();
  const bodyKey = squash(text.replace(/https?:\S+/g, "")).slice(0, 4000);
  const content_hash = await sha(fromEmail + "|" + squash(subject) + "|" + bodyKey);
  const noise = isNoise(from, subject);
  const status = noise ? "ignored" : (kind || tracking_no ? "unmatched" : "ignored");
  return { received_at: raw.date || raw.received_at || null, from_addr: from, subject, body: text, kind: noise ? null : kind, carrier,
    tracking_no, amount_eur, items_text, content_hash, status };
}

/* перепроверить все письма (после обновления разбора) */
async function reprocessAll() {
  const { data: mails } = await db.from("ops_mail").select("*").order("received_at", { ascending: true }).limit(2000);
  const stats: Record<string, number> = {};
  for (const m of mails ?? []) {
    const p = await parseMail(m);
    const upd: Record<string, unknown> = { subject: p.subject, kind: p.kind, carrier: p.carrier, tracking_no: p.tracking_no,
      amount_eur: p.amount_eur, items_text: p.items_text, content_hash: p.content_hash };
    if (m.status !== "matched" && m.status !== "ignored") upd.status = p.status;
    if (m.status === "unmatched" && p.status === "ignored") upd.status = "ignored";
    if (m.status === "duplicate") { upd.status = p.status; upd.order_id = null; }
    await db.from("ops_mail").update(upd).eq("id", m.id);
  }
  // дубли и привязка заново — по порядку прихода
  const { data: all } = await db.from("ops_mail").select("*").order("received_at", { ascending: true }).limit(2000);
  let orders = await activeOrders();
  for (const m of all ?? []) {
    if (m.status === "ignored") continue;
    if (m.status === "matched") {
      const { data: twin } = await db.from("ops_mail").select("id").eq("content_hash", m.content_hash).neq("id", m.id)
        .in("status", ["matched"]).lt("received_at", m.received_at).gte("received_at", new Date(new Date(m.received_at).getTime() - 21 * 864e5).toISOString()).limit(1);
      if (twin?.length) { await db.from("ops_mail").update({ status: "duplicate" }).eq("id", m.id); stats.duplicate = (stats.duplicate ?? 0) + 1; continue; }
      // обновить товар/службу по уже привязанному письму
      const o = orders.find((x) => x.id === m.order_id);
      if (o) { await applyMail(o, withDomain(m), null); orders = await activeOrders(); }
      stats.matched = (stats.matched ?? 0) + 1;
      continue;
    }
    const r = await processMail(m, orders);
    stats[r.status] = (stats[r.status] ?? 0) + 1;
    if (r.status === "matched" || r.status === "created") orders = await activeOrders();
  }
  return stats;
}

// после ввода № заказа или трека — ищем среди непривязанных писем
async function rematchFor(orderId: string) {
  const { data: o } = await db.from("ops_orders").select(ORDER_COLS).eq("id", orderId).single();
  if (!o || (!o.shop_order_no && !o.tracking_no)) return 0;
  const since = new Date(Date.now() - 90 * 864e5).toISOString();
  const { data: mails } = await db.from("ops_mail").select("*").eq("status", "unmatched").gte("received_at", since)
    .order("received_at", { ascending: true }).limit(500);
  let n = 0, cur = o as Order;
  for (const m of mails ?? []) {
    if (findOrders([cur], m).length) {
      const upd = await applyMail(cur, m, null); cur = { ...cur, ...upd } as Order; n++;
    }
  }
  return n;
}

/* объединить заказ-дубль (source) в основной (target) */
async function mergeOrders(targetId: string, sourceId: string, user_id: string) {
  if (targetId === sourceId) throw new Error("Это один и тот же заказ");
  const { data: rows } = await db.from("ops_orders").select("*").in("id", [targetId, sourceId]);
  const t = rows?.find((r) => r.id === targetId), s = rows?.find((r) => r.id === sourceId);
  if (!t || !s) throw new Error("Заказ не найден");
  if (t.merged_into || s.merged_into) throw new Error("Заказ уже объединён");
  const upd: Record<string, unknown> = {};
  const fill = ["client_name","client_phone","shop","shop_order_no","shop_domain","purchase_eur","address","carrier","tracking_no",
    "worker_id","flight_date","photo_path","received_at","parcel_delivered_at"];
  for (const f of fill) if ((t[f] == null || t[f] === "") && s[f] != null && s[f] !== "") upd[f] = s[f];
  if (!(+t.sale_tjs) && +s.sale_tjs) upd.sale_tjs = s.sale_tjs;
  if (t.delivery_mode === "pickup" && s.delivery_mode === "address") upd.delivery_mode = "address";
  const autoItems = (x: any) => x.auto_created && /bestell|order|sendung|paket|lieferung/i.test(x.items ?? "");
  if (s.items && s.items !== t.items) {
    if (!t.items || autoItems(t)) upd.items = s.items;
    else if (!autoItems(s) && !String(t.items).toLowerCase().includes(String(s.items).toLowerCase())) upd.items = `${t.items}; ${s.items}`;
  }
  if (s.notes && s.notes !== t.notes && !/^Создан автоматически/.test(s.notes)) upd.notes = [t.notes, s.notes].filter(Boolean).join("\n");
  // этап — тот, что дальше по цепочке (кроме «отменён»)
  const idx = (x: string) => (x === "cancelled" ? -1 : STAGES.indexOf(x));
  if (idx(s.stage) > idx(t.stage)) { upd.stage = s.stage; upd.stage_at = s.stage_at; }
  if (t.auto_created && !s.auto_created) upd.auto_created = false;
  // освободить уникальный № магазина у дубля
  await db.from("ops_orders").update({ merged_into: targetId, stage: "cancelled", shop_order_no: null,
    notes: `${s.notes ? s.notes + "\n" : ""}Объединён в заказ №${t.num}` }).eq("id", sourceId);
  if (Object.keys(upd).length) { const { error } = await db.from("ops_orders").update(upd).eq("id", targetId); if (error) throw error; }
  await db.from("ops_mail").update({ order_id: targetId }).eq("order_id", sourceId);
  await db.from("ops_payments").update({ order_id: targetId }).eq("order_id", sourceId);
  await db.from("ops_expenses").update({ order_id: targetId }).eq("order_id", sourceId);
  await log(user_id, "merge_orders", targetId, { from: sourceId, from_num: s.num, ...upd });
  return { num: t.num };
}

/* ================= основной обработчик ================= */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const body = await req.json();
    if (body.action === "ingest") return await ingest(body);

    const pin = String(body.pin ?? "");
    const since = new Date(Date.now() - 15 * 60e3).toISOString();
    const { count } = await db.from("ops_log").select("id", { count: "exact", head: true })
      .eq("action", "login_fail").gte("at", since);
    if ((count ?? 0) > 30) return json({ error: "Слишком много попыток, подождите 15 минут" }, 429);

    const { data: me } = await db.from("ops_users").select("id,name,role")
      .eq("pin_hash", await sha(PEPPER + pin)).eq("active", true).maybeSingle();
    if (!me) { await log(null, "login_fail"); await new Promise((r) => setTimeout(r, 800)); return json({ error: "Неверный PIN" }, 401); }

    const a = body.action;
    const isAdmin = me.role === "admin", isSeller = me.role === "seller", isWorker = me.role === "worker";

    if (a === "me") return json({ me });

    if (a === "list") {
      let q = db.from("ops_orders").select("*").is("merged_into", null).order("created_at", { ascending: false }).limit(1000);
      if (isWorker) q = q.in("stage", ["purchased","shipped","received"]).or(`worker_id.is.null,worker_id.eq.${me.id}`);
      const { data: orders, error } = await q;
      if (error) throw error;
      const paths = orders.filter((o) => o.photo_path).map((o) => o.photo_path);
      const urls: Record<string, string> = {};
      if (paths.length) {
        const { data: s } = await db.storage.from("ops-photos").createSignedUrls(paths, 3600);
        s?.forEach((x) => { if (x.path && x.signedUrl) urls[x.path] = x.signedUrl; });
      }
      let out: any[] = orders.map((o) => ({ ...o, photo_url: o.photo_path ? urls[o.photo_path] : null }));
      if (isWorker) {
        out = out.map(({ id, num, client_name, items, shop, carrier, tracking_no, stage, stage_at, photo_url, created_at, parcel_delivered_at }) =>
          ({ id, num, client_name, items, shop, carrier, tracking_no, stage, stage_at, photo_url, created_at, parcel_delivered_at }));
        return json({ me, orders: out });
      }
      const [{ data: payments }, { data: expenses }, { data: settings }, { data: users }, { data: mails }] = await Promise.all([
        db.from("ops_payments").select("*").order("paid_at", { ascending: false }),
        isAdmin ? db.from("ops_expenses").select("*").order("spent_at", { ascending: false }) : Promise.resolve({ data: [] }),
        db.from("ops_settings").select("*"),
        db.from("ops_users").select("id,name,role").eq("active", true),
        db.from("ops_mail").select("id,received_at,from_addr,subject,kind,carrier,tracking_no,amount_eur,items_text,status,order_id")
          .in("status", ["unmatched","matched","duplicate"]).order("received_at", { ascending: false }).limit(600),
      ]);
      const st = Object.fromEntries((settings ?? []).filter((s) => !HIDDEN_SETTINGS.includes(s.key)).map((s) => [s.key, s.value]));
      return json({ me, orders: out, payments, expenses, settings: st, users, mails });
    }

    if (a === "save_order") {
      if (!(isAdmin || isSeller)) return json({ error: "Нет доступа" }, 403);
      const o: Record<string, unknown> = {};
      for (const f of ORDER_FIELDS) if (f in (body.order ?? {})) o[f] = body.order[f] === "" ? null : body.order[f];
      // тот же № заказа магазина уже есть в другом заказе — подсказать объединить, а не плодить дубль
      if (o.shop_order_no) {
        const ex = await findByShopNo(String(o.shop_order_no));
        if (ex && ex.id !== body.order?.id)
          return json({ error: `№ заказа магазина ${o.shop_order_no} уже есть в заказе №${ex.num}. Откройте его или объедините заказы.`, dup_order: ex.num }, 409);
      }
      let saved;
      if (body.order?.id) {
        const { data, error } = await db.from("ops_orders").update(o).eq("id", body.order.id).select().single();
        if (error) throw error; await log(me.id, "update_order", data.id, o); saved = data;
      } else {
        if (!o.client_name || !o.items) return json({ error: "Нужны клиент и товар" }, 400);
        const { data, error } = await db.from("ops_orders").insert({ ...o, created_by: me.id }).select().single();
        if (error) throw error;
        const paid = Number(body.paid_tjs || 0);
        if (paid > 0) await db.from("ops_payments").insert({ order_id: data.id, amount_tjs: paid, created_by: me.id, note: "при заказе" });
        await log(me.id, "create_order", data.id); saved = data;
      }
      const matched = (o.shop_order_no || o.tracking_no) ? await rematchFor(saved.id) : 0;
      return json({ order: saved, matched });
    }

    if (a === "merge_orders") {
      if (!(isAdmin || isSeller)) return json({ error: "Нет доступа" }, 403);
      return json({ ok: true, ...(await mergeOrders(body.target_id, body.source_id, me.id)) });
    }

    if (a === "reprocess_mail") {
      if (!isAdmin) return json({ error: "Нет доступа" }, 403);
      const stats = await reprocessAll();
      await db.from("ops_settings").upsert({ key: "mail_parser", value: "2" });
      return json({ ok: true, stats });
    }

    if (a === "link_mail") {
      if (!(isAdmin || isSeller)) return json({ error: "Нет доступа" }, 403);
      const ids: string[] = Array.isArray(body.mail_ids) ? body.mail_ids : [body.mail_id];
      const { data: ms } = await db.from("ops_mail").select("*").in("id", ids).order("received_at");
      let { data: o } = await db.from("ops_orders").select(ORDER_COLS).eq("id", body.order_id).single();
      if (!ms?.length || !o) return json({ error: "Не найдено" }, 404);
      for (const m of ms) { const upd = await applyMail(o as Order, withDomain(m), me.id); o = { ...o, ...upd } as any; }
      return json({ ok: true });
    }

    if (a === "hide_mail") {
      if (!(isAdmin || isSeller)) return json({ error: "Нет доступа" }, 403);
      const ids: string[] = Array.isArray(body.mail_ids) ? body.mail_ids : [body.mail_id];
      const { error } = await db.from("ops_mail").update({ status: "ignored" }).in("id", ids);
      if (error) throw error; return json({ ok: true });
    }

    if (a === "set_stage") {
      const { id, stage } = body;
      if (!STAGES.includes(stage)) return json({ error: "Неверный этап" }, 400);
      const { data: cur } = await db.from("ops_orders").select("id,stage,worker_id,photo_path").eq("id", id).single();
      if (!cur) return json({ error: "Заказ не найден" }, 404);
      if (isWorker) {
        if (!["received","airport"].includes(stage)) return json({ error: "Нет доступа" }, 403);
        if (cur.worker_id && cur.worker_id !== me.id) return json({ error: "Не ваш заказ" }, 403);
        if (!["purchased","shipped","received"].includes(cur.stage)) return json({ error: "Заказ уже дальше по цепочке" }, 400);
      }
      const upd: Record<string, unknown> = { stage, stage_at: new Date().toISOString() };
      if (stage === "received") { upd.received_at = upd.stage_at; if (isWorker) upd.worker_id = me.id; }
      if (body.photo) {
        const m = String(body.photo).match(/^data:(image\/(jpeg|png|webp));base64,(.+)$/);
        if (!m) return json({ error: "Плохое фото" }, 400);
        const bytes = Uint8Array.from(atob(m[3]), (c) => c.charCodeAt(0));
        if (bytes.length > 3 * 1024 * 1024) return json({ error: "Фото слишком большое" }, 400);
        const path = `${id}/${Date.now()}.${m[2] === "jpeg" ? "jpg" : m[2]}`;
        const { error: ue } = await db.storage.from("ops-photos").upload(path, bytes, { contentType: m[1] });
        if (ue) throw ue;
        upd.photo_path = path;
      }
      const { error } = await db.from("ops_orders").update(upd).eq("id", id);
      if (error) throw error;
      await log(me.id, "stage", id, { stage, photo: !!body.photo }); return json({ ok: true });
    }

    if (a === "add_payment") {
      if (!(isAdmin || isSeller)) return json({ error: "Нет доступа" }, 403);
      const amt = Number(body.amount_tjs);
      if (!body.order_id || !amt) return json({ error: "Нужна сумма" }, 400);
      const { error } = await db.from("ops_payments").insert({ order_id: body.order_id, amount_tjs: amt, note: body.note || null, paid_at: body.paid_at || undefined, created_by: me.id });
      if (error) throw error; await log(me.id, "payment", body.order_id, { amt }); return json({ ok: true });
    }

    if (a === "add_expense") {
      if (!isAdmin) return json({ error: "Нет доступа" }, 403);
      const e = body.expense ?? {};
      const { error } = await db.from("ops_expenses").insert({ spent_at: e.spent_at || undefined, category: e.category, amount: Number(e.amount),
        currency: e.currency || "EUR", order_id: e.order_id || null, note: e.note || null, created_by: me.id });
      if (error) throw error; await log(me.id, "expense", null, e); return json({ ok: true });
    }

    if (a === "delete_expense" || a === "delete_payment") {
      if (!isAdmin) return json({ error: "Нет доступа" }, 403);
      const { error } = await db.from(a === "delete_expense" ? "ops_expenses" : "ops_payments").delete().eq("id", body.id);
      if (error) throw error; await log(me.id, a, null, { id: body.id }); return json({ ok: true });
    }

    if (a === "set_setting") {
      if (!isAdmin) return json({ error: "Нет доступа" }, 403);
      if (!["eur_tjs","delay_days"].includes(body.key)) return json({ error: "Неверная настройка" }, 400);
      const { error } = await db.from("ops_settings").upsert({ key: body.key, value: String(body.value) });
      if (error) throw error; return json({ ok: true });
    }

    return json({ error: "Неизвестное действие" }, 400);
  } catch (e) {
    console.error(e);
    return json({ error: (e as Error).message ?? "Ошибка" }, 500);
  }
});
