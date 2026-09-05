// Lean compiler output
// Module: AirsLean.Soundness.FundsAIRs
// Imports: public import Init public meta import Init public import AirsLean.Soundness.ActionAIRs
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
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_MaxTotalBet;
static lean_object* _init_lp_airs__lean_AirsLean_MaxTotalBet(void){
_start:
{
lean_object* v___x_1_; 
v___x_1_ = lean_cstr_to_nat("1000000000000000000");
return v___x_1_;
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Soundness_ActionAIRs(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Soundness_FundsAIRs(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Soundness_ActionAIRs(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
lp_airs__lean_AirsLean_MaxTotalBet = _init_lp_airs__lean_AirsLean_MaxTotalBet();
lean_mark_persistent(lp_airs__lean_AirsLean_MaxTotalBet);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
