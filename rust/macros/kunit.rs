// SPDX-License-Identifier: GPL-2.0

//! Procedural macro to run KUnit tests using a user-space like syntax.
//!
//! Copyright (c) 2023 José Expósito <jose.exposito89@gmail.com>

use std::ffi::CString;

use proc_macro2::TokenStream;
use quote::{
    format_ident,
    quote,
    ToTokens, //
};
use syn::{
    parse_quote,
    Error,
    Ident,
    Item,
    ItemMod,
    LitCStr,
    Result, //
};

pub(crate) fn kunit_tests(test_suite: Ident, mut module: ItemMod) -> Result<TokenStream> {
    if test_suite.to_string().len() > 255 {
        return Err(Error::new_spanned(
            test_suite,
            "test suite names cannot exceed the maximum length of 255 bytes",
        ));
    }

    // We cannot handle modules that defer to another file (e.g. `mod foo;`).
    let Some((module_brace, module_items)) = module.content.take() else {
        Err(Error::new_spanned(
            module,
            "`#[kunit_tests(test_name)]` attribute should only be applied to inline modules",
        ))?
    };

    // Make the entire module gated behind `CONFIG_KUNIT`.
    module
        .attrs
        .insert(0, parse_quote!(#[cfg(CONFIG_KUNIT="y")]));

    let mut processed_items = Vec::new();
    let mut test_cases = Vec::new();
    let mut test_cases_cfgs = Vec::new();
    let mut test_case_number: u32 = 1;

    // Generate the test KUnit test suite and a test case for each `#[test]`.
    //
    // The code generated for the following test module:
    //
    // ```
    // #[kunit_tests(kunit_test_suit_name)]
    // mod tests {
    //     #[test]
    //     fn foo() {
    //         assert_eq!(1, 1);
    //     }
    //
    //     #[test]
    //     fn bar() {
    //         assert_eq!(2, 2);
    //     }
    // }
    // ```
    //
    // Looks like:
    //
    // ```
    // unsafe extern "C" fn kunit_rust_wrapper_foo(_test: *mut ::kernel::bindings::kunit) { foo(); }
    // unsafe extern "C" fn kunit_rust_wrapper_bar(_test: *mut ::kernel::bindings::kunit) { bar(); }
    //
    // static mut TEST_CASES: [::kernel::bindings::kunit_case; 3] = [
    //     ::kernel::kunit::kunit_case(c"foo", kunit_rust_wrapper_foo),
    //     ::kernel::kunit::kunit_case(c"bar", kunit_rust_wrapper_bar),
    //     ::pin_init::zeroed(),
    // ];
    //
    // ::kernel::kunit_unsafe_test_suite!(kunit_test_suit_name, TEST_CASES);
    // ```
    //
    // Non-function items (e.g. imports) are preserved.
    for item in module_items {
        let Item::Fn(mut f) = item else {
            processed_items.push(item);
            continue;
        };

        if f.attrs
            .extract_if(.., |attr| attr.path().is_ident("test"))
            .count()
            == 0
        {
            processed_items.push(Item::Fn(f));
            continue;
        }

        let test = f.sig.ident.clone();

        // Retrieve `#[cfg]` applied on the function which needs to be present on derived items too.
        let cfg_attrs: Vec<_> = f
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .cloned()
            .collect();

        let should_panic = f
            .attrs
            .extract_if(.., |attr| attr.path().is_ident("should_panic"))
            .count()
            > 0;

        // Inside the test, override usual `assert!` and `assert_eq!` macros with ones that call
        // KUnit instead unless the test should panic. For tests expected to panic, assertions are
        // not overwritten so they can be handled by the Rust's panic handler.
        let test_str = test.to_string();
        if !should_panic {
            f.block.stmts.insert(
                0,
                parse_quote! {
                    #[allow(unused)]
                    macro_rules! assert {
                        ($cond:expr $(,)?) => {{
                            kernel::kunit_assert!(#test_str, $cond);
                        }}
                    }
                },
            );
            f.block.stmts.insert(
                0,
                parse_quote! {
                    #[allow(unused)]
                    macro_rules! assert_eq {
                        ($left:expr, $right:expr $(,)?) => {{
                            kernel::kunit_assert_eq!(#test_str, $left, $right);
                        }}
                    }
                },
            );
        }

        // Add back the test item.
        processed_items.push(Item::Fn(f));

        let kunit_wrapper_fn_name = format_ident!("kunit_rust_wrapper_{test}_{test_case_number}");
        let test_cstr = LitCStr::new(
            &CString::new(test_str.as_str()).expect("identifier cannot contain NUL"),
            test.span(),
        );
        let assertion = if should_panic {
            quote!(
                let _ = #test();
                ::kernel::kunit::err(::kernel::prelude::fmt!(
                    "    Expected {} to panic\n", #test_str
                ));
                (*_test).status = ::kernel::bindings::kunit_status_KUNIT_FAILURE;
            )
        } else {
            quote!(
                use ::kernel::kunit::is_test_result_ok;
                kernel::kunit_assert!(#test_str, is_test_result_ok(#test()));
            )
        };
        processed_items.push(parse_quote! {
            // Prepend any `cfg` attributes before the function declaration to activate it only in
            // cases the configs are on
            #(#cfg_attrs)*
            unsafe extern "C" fn #kunit_wrapper_fn_name(_test: *mut ::kernel::bindings::kunit) {
                (*_test).status = ::kernel::bindings::kunit_status_KUNIT_SUCCESS;
                #assertion
            }
        });

        test_cases.push(quote!({
            let mut case = ::kernel::kunit::kunit_case(#test_cstr, #kunit_wrapper_fn_name);
            case.attr.rust_should_panic = #should_panic;
            case
        }));
        test_cases_cfgs.push(cfg_attrs);
        test_case_number += 1;
    }

    // This dummy array is used to calculate the exact number of tests cases that are active
    // depending on their #[cfg(...)] attribute.
    processed_items.push(parse_quote!(
        const TEST_CASES_COUNT: &[()] = &[#(#(#test_cases_cfgs)* (),)* ()];
    ));

    processed_items.push(parse_quote! {
        static mut TEST_CASES: [::kernel::bindings::kunit_case; TEST_CASES_COUNT.len()] = [
            #(#(#test_cases_cfgs)* { #test_cases },)*
            ::pin_init::zeroed()
        ];
    });

    processed_items.push(parse_quote! {
        ::kernel::kunit_unsafe_test_suite!(#test_suite, TEST_CASES);
    });

    module.content = Some((module_brace, processed_items));
    Ok(module.to_token_stream())
}
