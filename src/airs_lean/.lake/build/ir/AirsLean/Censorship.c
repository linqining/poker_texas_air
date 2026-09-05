// Lean compiler output
// Module: AirsLean.Censorship
// Imports: public import Init public meta import Init public import AirsLean.Censorship.ActionSig public import AirsLean.Censorship.ActionLog public import AirsLean.Censorship.AcceptedSeq public import AirsLean.Censorship.AutoAction public import AirsLean.Censorship.DigestBinding
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_ActionSig(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_ActionLog(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_AcceptedSeq(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_AutoAction(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_DigestBinding(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Censorship(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_ActionSig(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_ActionLog(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_AcceptedSeq(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_AutoAction(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_DigestBinding(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
