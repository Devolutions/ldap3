use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use crate::conn::{LdapConnAsync, LdapConnSettings};
use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::ldap::{Ldap, Mod};
use crate::result::{CompareResult, ExopResult, LdapResult, Result, SearchResult};
use crate::search::{ResultEntry, Scope, SearchOptions, SearchStream};
use crate::RequestId;

use tokio::runtime::{self, Runtime};

/// Synchronous connection to an LDAP server.
///
/// In the synchronous version of the interface, [`new()`](#method.new) will return
/// a struct encapsulating a runtime, the connection, and an operation handle. All
/// operations are performed through that struct, synchronously: the thread will
/// wait until the result is available or the operation times out.
///
/// The API is virtually identical to the asynchronous one. The chief difference is
/// that `LdapConn` is not cloneable: if you need another handle, you must open a
/// new connection.
#[derive(Debug)]
pub struct LdapConn {
    rt: Arc<Runtime>,
    ldap: Ldap,
}

impl LdapConn {
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub fn new(url: &str) -> Result<Self> {
        Self::with_settings(LdapConnSettings::new(), url)
    }

    /// Open a connection to an LDAP server specified by `url`.
    ///
    /// See [LdapConnAsync::new()](struct.LdapConnAsync.html#method.new) for the
    /// details of the supported URL formats.
    pub fn with_settings(settings: LdapConnSettings, url: &str) -> Result<Self> {
        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()?;
        let ldap = rt.block_on(async move {
            let (conn, ldap) = match LdapConnAsync::with_settings(settings, url).await {
                Ok((conn, ldap)) => (conn, ldap),
                Err(e) => return Err(e),
            };
            super::drive!(conn);
            Ok(ldap)
        })?;
        Ok(LdapConn {
            ldap,
            rt: Arc::new(rt),
        })
    }

    /// See [`Ldap::with_search_options()`](struct.Ldap.html#method.with_search_options).
    pub fn with_search_options(&mut self, opts: SearchOptions) -> &mut Self {
        self.ldap.search_opts = Some(opts);
        self
    }

    /// See [`Ldap::with_controls()`](struct.Ldap.html#method.with_controls).
    pub fn with_controls<V: IntoRawControlVec>(&mut self, ctrls: V) -> &mut Self {
        self.ldap.controls = Some(ctrls.into());
        self
    }

    /// See [`Ldap::with_timeout()`](struct.Ldap.html#method.with_timeout).
    pub fn with_timeout(&mut self, duration: Duration) -> &mut Self {
        self.ldap.timeout = Some(duration);
        self
    }

    /// See [`Ldap::simple_bind()`](struct.Ldap.html#method.simple_bind).
    pub fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.simple_bind(bind_dn, bind_pw).await })
    }

    /// See [`Ldap::sasl_external_bind()`](struct.Ldap.html#method.sasl_external_bind).
    pub fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_external_bind().await })
    }

    pub fn sasl_spnego_bind(&mut self, username: &str, password: &str) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_spnego_bind(username, password).await })
    }

    /// See [`Ldap::search()`](struct.Ldap.html#method.search).
    pub fn search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<SearchResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.search(base, scope, filter, attrs).await })
    }

    /// Perform a Search, but unlike `search()`, which returns all results at once, return a handle which
    /// will be used for retrieving entries one by one. See [`EntryStream`](struct.EntryStream.html)
    /// for the explanation of the protocol which must be adhered to in this case.
    pub fn streaming_search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<EntryStream> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        let stream =
            rt.block_on(async move { ldap.streaming_search(base, scope, filter, attrs).await })?;
        Ok(EntryStream {
            stream,
            rt: self.rt.clone(),
        })
    }

    /// See [`Ldap::add()`](struct.Ldap.html#method.add).
    pub fn add<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        attrs: Vec<(S, HashSet<S>)>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.add(dn, attrs).await })
    }

    /// See [`Ldap::compare()`](struct.Ldap.html#method.compare).
    pub fn compare<B: AsRef<[u8]>>(
        &mut self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Result<CompareResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.compare(dn, attr, val).await })
    }

    /// See [`Ldap::delete()`](struct.Ldap.html#method.delete).
    pub fn delete(&mut self, dn: &str) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.delete(dn).await })
    }

    /// See [`Ldap::modify()`](struct.Ldap.html#method.modify).
    pub fn modify<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        mods: Vec<Mod<S>>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modify(dn, mods).await })
    }

    /// See [`Ldap::modifydn()`](struct.Ldap.html#method.modifydn).
    pub fn modifydn(
        &mut self,
        dn: &str,
        rdn: &str,
        delete_old: bool,
        new_sup: Option<&str>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modifydn(dn, rdn, delete_old, new_sup).await })
    }

    /// See [`Ldap::unbind()`](struct.Ldap.html#method.unbind).
    pub fn unbind(&mut self) -> Result<()> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.unbind().await })
    }

    /// See [`Ldap::extended()`](struct.Ldap.html#method.extended).
    pub fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.extended(exop).await })
    }

    /// See [`Ldap::last_id()`](struct.Ldap.html#method.last_id).
    pub fn last_id(&mut self) -> RequestId {
        self.ldap.last_id()
    }

    /// See [`Ldap::abandon()`](struct.Ldap.html#method.abandon).
    pub fn abandon(&mut self, msgid: RequestId) -> Result<()> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.abandon(msgid).await })
    }
}

/// Handle for obtaining a stream of search results.
///
/// For compatibility, this struct's name is different from the async version
/// which is [`SearchStream`](struct.SearchStream.html). The protocol and behavior
/// are the same, with one important difference: an `EntryStream` shares the
/// Tokio runtime with `LdapConn` from which it's obtained, but the two can't be
/// used in parallel. Thefore, don't try to send an `EntryStream` to a different
/// thread.
pub struct EntryStream {
    stream: SearchStream,
    rt: Arc<Runtime>,
}

impl EntryStream {
    /// See [`SearchStream::next()`](struct.SearchStream.html#method.next).
    pub fn next(&mut self) -> Result<Option<ResultEntry>> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let stream = &mut self.stream;
        rt.block_on(async move { stream.next().await })
    }

    /// See [`SearchStream::finish()`](struct.SearchStream.html#method.finish).
    ///
    /// The name `result()` was kept for backwards compatibility.
    pub fn result(self) -> LdapResult {
        self.stream.finish()
    }

    /// See [`SearchStream::last_id()`](struct.SearchStream.html#method.last_id).
    pub fn last_id(&mut self) -> RequestId {
        self.stream.last_id()
    }
}
