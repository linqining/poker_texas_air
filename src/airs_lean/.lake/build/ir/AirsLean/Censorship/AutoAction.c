// Lean compiler output
// Module: AirsLean.Censorship.AutoAction
// Imports: public import Init public meta import Init public import AirsLean.Censorship.AcceptedSeq
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
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_isAutoOf(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_isAutoOf___boxed(lean_object*);
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_isAutoOf(lean_object* v_x_1_){
_start:
{
uint8_t v___x_2_; 
v___x_2_ = 1;
return v___x_2_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_isAutoOf___boxed(lean_object* v_x_3_){
_start:
{
uint8_t v_res_4_; lean_object* v_r_5_; 
v_res_4_ = lp_airs__lean_AirsLean_isAutoOf(v_x_3_);
lean_dec(v_x_3_);
v_r_5_ = lean_box(v_res_4_);
return v_r_5_;
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_AcceptedSeq(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Censorship_AutoAction(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_AcceptedSeq(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
