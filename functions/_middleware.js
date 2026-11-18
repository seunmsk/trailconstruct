// Sends www.trailconstruct.com to trailconstruct.com so there's one address (and one sign-in).
export async function onRequest(ctx) {
  const u = new URL(ctx.request.url);
  if (u.hostname === "www.trailconstruct.com") {
    u.hostname = "trailconstruct.com";
    return Response.redirect(u.toString(), 301);
  }
  return ctx.next();
}
