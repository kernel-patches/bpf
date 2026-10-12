// SPDX-License-Identifier: Apache-2.0 OR MIT

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, ToTokens};
use syn::{Attribute, GenericParam, Generics, Index, Member, Token};

use crate::DiagCtxt;

pub(crate) trait AttrListExt {
    fn extract_cfg_attrs(&mut self) -> Vec<TokenStream>;

    /// Extract attribute with identifier `path`.
    ///
    /// Report error if the attribute appears multiple times.
    fn extract_single_attr(&mut self, dcx: &DiagCtxt, path: &str) -> Option<Attribute>;
}

impl AttrListExt for Vec<Attribute> {
    fn extract_cfg_attrs(&mut self) -> Vec<TokenStream> {
        let cfg: Vec<_> = self
            .iter()
            .filter(|a| a.path().is_ident("cfg"))
            .map(|a| {
                a.parse_args::<TokenStream>()
                    .expect("parse as token stream cannot fail")
            })
            .collect();

        if !cfg.is_empty() {
            self.retain(|a| !a.path().is_ident("cfg"));
        }

        cfg
    }

    fn extract_single_attr(&mut self, dcx: &DiagCtxt, path: &str) -> Option<Attribute> {
        // FIXME: Replace with `extract_if` when MSRV >= 1.85.
        let attr_pos = self.iter().position(|attr| attr.path().is_ident(path))?;
        let attr = self.remove(attr_pos);
        self.retain(|attr| {
            if !attr.path().is_ident(path) {
                return true;
            }

            dcx.error(
                attr,
                format!("`#[{path}]` attribute specified more than once"),
            );
            false
        });
        Some(attr)
    }
}

pub(crate) trait MemberExt {
    /// Returns an identifier for the member.
    ///
    /// Tuple fields have no name of their own, so they are named `_0`, `_1`, ... instead.
    fn as_ident(&self) -> Ident;

    /// Obtain a display name for the member in diagnostics.
    fn display_name(&self) -> String;
}

impl MemberExt for Member {
    fn as_ident(&self) -> Ident {
        match self {
            Member::Named(ident) => ident.clone(),
            Member::Unnamed(Index { index, span }) => format_ident!("_{index}", span = *span),
        }
    }

    fn display_name(&self) -> String {
        match self {
            Member::Named(ident) => format!("`{ident}`"),
            Member::Unnamed(Index { index, .. }) => format!("index `{index}`"),
        }
    }
}

pub(crate) struct CombinedGenerics<'a>(pub(crate) Vec<&'a Generics>);
pub(crate) struct CombinedImplGenerics<'a>(&'a CombinedGenerics<'a>);
pub(crate) struct CombinedTypeGenerics<'a>(&'a CombinedGenerics<'a>);

impl CombinedGenerics<'_> {
    pub(crate) fn split_for_impl(
        &self,
    ) -> (
        CombinedImplGenerics<'_>,
        CombinedTypeGenerics<'_>,
        // A stub type so `split_for_impl` signature matches that of `syn`'s.
        impl Sized,
    ) {
        (CombinedImplGenerics(self), CombinedTypeGenerics(self), ())
    }
}

impl ToTokens for CombinedGenerics<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // Most of the time we are only adding lifetimes, so we prefer to place
        // the user provided generics last.
        self.0
            .last()
            .and_then(|x| x.lt_token)
            .unwrap_or_default()
            .to_tokens(tokens);

        let comma: Token![,] = Default::default();

        // Output lifetimes first.
        for generics in self.0.iter() {
            for param in generics.params.pairs() {
                if let GenericParam::Lifetime(lt) = param.value() {
                    lt.to_tokens(tokens);
                    param.punct().unwrap_or(&&comma).to_tokens(tokens);
                }
            }
        }

        for generics in self.0.iter() {
            for param in generics.params.pairs() {
                if let GenericParam::Lifetime(_) = param.value() {
                    continue;
                };
                param.value().to_tokens(tokens);
                param.punct().unwrap_or(&&comma).to_tokens(tokens);
            }
        }

        self.0
            .last()
            .and_then(|x| x.gt_token)
            .unwrap_or_default()
            .to_tokens(tokens);
    }
}

impl ToTokens for CombinedImplGenerics<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.0
             .0
            .last()
            .and_then(|x| x.lt_token)
            .unwrap_or_default()
            .to_tokens(tokens);

        let comma: Token![,] = Default::default();

        // Output lifetimes first.
        for generics in self.0 .0.iter() {
            for param in generics.params.pairs() {
                if let GenericParam::Lifetime(lt) = param.value() {
                    lt.to_tokens(tokens);
                    param.punct().unwrap_or(&&comma).to_tokens(tokens);
                }
            }
        }

        for generics in self.0 .0.iter() {
            for param in generics.params.pairs() {
                // Leave out defaults.
                match param.value() {
                    GenericParam::Lifetime(_) => continue,
                    GenericParam::Type(param) => {
                        param.ident.to_tokens(tokens);
                        if !param.bounds.is_empty() {
                            param
                                .colon_token
                                .unwrap_or_else(Default::default)
                                .to_tokens(tokens);
                            param.bounds.to_tokens(tokens);
                        }
                    }
                    GenericParam::Const(param) => {
                        param.const_token.to_tokens(tokens);
                        param.ident.to_tokens(tokens);
                        param.colon_token.to_tokens(tokens);
                        param.ty.to_tokens(tokens);
                    }
                }
                param.punct().unwrap_or(&&comma).to_tokens(tokens);
            }
        }

        self.0
             .0
            .last()
            .and_then(|x| x.gt_token)
            .unwrap_or_default()
            .to_tokens(tokens);
    }
}

impl ToTokens for CombinedTypeGenerics<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.0
             .0
            .last()
            .and_then(|x| x.lt_token)
            .unwrap_or_default()
            .to_tokens(tokens);

        let comma: Token![,] = Default::default();

        // Output lifetimes first.
        for generics in self.0 .0.iter() {
            for param in generics.params.pairs() {
                if let GenericParam::Lifetime(lt) = param.value() {
                    // Leave out bounds
                    lt.lifetime.to_tokens(tokens);
                    param.punct().unwrap_or(&&comma).to_tokens(tokens);
                }
            }
        }

        for generics in self.0 .0.iter() {
            for param in generics.params.pairs() {
                // Leave out bounds and defaults.
                match param.value() {
                    GenericParam::Lifetime(_) => continue,
                    GenericParam::Type(param) => {
                        param.ident.to_tokens(tokens);
                    }
                    GenericParam::Const(param) => {
                        param.ident.to_tokens(tokens);
                    }
                }
                param.punct().unwrap_or(&&comma).to_tokens(tokens);
            }
        }

        self.0
             .0
            .last()
            .and_then(|x| x.gt_token)
            .unwrap_or_default()
            .to_tokens(tokens);
    }
}
