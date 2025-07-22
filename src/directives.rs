use crate::constants;
use crate::error::CspError;
use crate::source::Source;
use crate::utils::BufferWriter;
use bytes::BytesMut;
use rustc_hash::FxHashSet;
use smallvec::{smallvec, SmallVec};
use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive {
    name: Cow<'static, str>,
    sources: SmallVec<[Source; 4]>,
    fallback_sources: Option<SmallVec<[Source; 2]>>,
}

impl Default for Directive {
    fn default() -> Self {
        Self {
            name: Cow::Borrowed(""),
            sources: SmallVec::new(),
            fallback_sources: None,
        }
    }
}

impl Directive {
    #[inline]
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            sources: SmallVec::new(),
            fallback_sources: None,
        }
    }

    pub fn add_source(&mut self, source: Source) -> &mut Self {
        if source.is_none() {
            self.sources.clear();
            self.sources.push(source);
        } else if !self.sources.is_empty() && self.sources[0].is_none() {
            self.sources.clear();
            self.sources.push(source);
        } else if !self.sources.iter().any(|s| s == &source) {
            self.sources.push(source);
        }
        self
    }

    pub fn add_sources<I>(&mut self, sources: I) -> &mut Self
    where
        I: IntoIterator<Item = Source>,
    {
        for source in sources {
            self.add_source(source);
        }
        self
    }

    pub fn add_fallback_sources<I>(&mut self, sources: I) -> &mut Self
    where
        I: IntoIterator<Item = Source>,
    {
        let fallback = self.fallback_sources.get_or_insert_with(|| smallvec![]);
        fallback.extend(sources);
        self
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    #[inline]
    pub fn fallback_sources(&self) -> Option<&[Source]> {
        self.fallback_sources.as_deref()
    }

    pub fn validate(&self) -> Result<(), CspError> {
        if self.sources.len() > 1 && self.sources.iter().any(|s| s.is_none()) {
            return Err(CspError::ValidationError(format!(
                "Directive '{}' contains 'none' with other sources",
                self.name
            )));
        }

        for source in &self.sources {
            match source {
                Source::Host(host) if host.is_empty() => {
                    return Err(CspError::ValidationError(format!(
                        "Directive '{}' contains empty host",
                        self.name
                    )));
                }
                Source::Scheme(scheme) if scheme.is_empty() => {
                    return Err(CspError::ValidationError(format!(
                        "Directive '{}' contains empty scheme",
                        self.name
                    )));
                }
                Source::Nonce(nonce) if nonce.is_empty() => {
                    return Err(CspError::ValidationError(format!(
                        "Directive '{}' contains empty nonce",
                        self.name
                    )));
                }
                Source::Hash { value, .. } if value.is_empty() => {
                    return Err(CspError::ValidationError(format!(
                        "Directive '{}' contains empty hash",
                        self.name
                    )));
                }
                _ => {}
            }
        }

        Ok(())
    }

    #[inline]
    pub fn estimated_size(&self) -> usize {
        let mut size = self.name.len();

        if !self.sources.is_empty() {
            size += 1;
            size += self
                .sources
                .iter()
                .map(|s| s.estimated_size())
                .sum::<usize>();
            size += self.sources.len().saturating_sub(1);
        }

        if let Some(fallback) = &self.fallback_sources {
            if !fallback.is_empty() {
                size += fallback.iter().map(|s| s.estimated_size()).sum::<usize>();
                size += fallback.len();
            }
        }

        size
    }

    #[inline]
    pub fn contains_nonce(&self) -> bool {
        self.sources.iter().any(|s| s.contains_nonce())
    }

    #[inline]
    pub fn contains_hash(&self) -> bool {
        self.sources.iter().any(|s| s.contains_hash())
    }
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;

        if !self.sources.is_empty() {
            f.write_str(" ")?;
            let mut first = true;
            for source in &self.sources {
                if !first {
                    f.write_str(" ")?;
                }
                write!(f, "{}", source)?;
                first = false;
            }
        }

        if let Some(fallback) = &self.fallback_sources {
            if !fallback.is_empty() {
                for source in fallback {
                    f.write_str(" ")?;
                    write!(f, "{}", source)?;
                }
            }
        }

        Ok(())
    }
}

impl BufferWriter for Directive {
    fn write_to_buffer(&self, buffer: &mut BytesMut) {
        buffer.extend_from_slice(self.name.as_bytes());

        if !self.sources.is_empty() {
            buffer.extend_from_slice(b" ");

            if self.sources.len() == 1 {
                self.sources[0].write_to_buffer(buffer);
            } else {
                let mut first = true;
                for source in &self.sources {
                    if !first {
                        buffer.extend_from_slice(b" ");
                    }
                    source.write_to_buffer(buffer);
                    first = false;
                }
            }
        }

        if let Some(fallback) = &self.fallback_sources {
            if !fallback.is_empty() {
                for source in fallback {
                    buffer.extend_from_slice(b" ");
                    source.write_to_buffer(buffer);
                }
            }
        }
    }
}

impl Hash for Directive {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.sources.hash(state);
        self.fallback_sources.hash(state);
    }
}

pub trait DirectiveSpec: Sized {
    const NAME: &'static str;

    fn add_source(mut self, source: Source) -> Self {
        self.inner_mut().add_source(source);
        self
    }

    fn add_sources<I>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = Source>,
    {
        for source in sources {
            self.inner_mut().add_source(source);
        }
        self
    }

    fn fallback_sources<I>(mut self, sources: I) -> Self
    where
        I: IntoIterator<Item = Source>,
    {
        self.inner_mut().add_fallback_sources(sources);
        self
    }

    fn inner_mut(&mut self) -> &mut Directive;

    fn build(self) -> Directive;
}

macro_rules! define_directive {
    ($name:ident, $directive_name:expr) => {
        #[derive(Debug, Clone, Default)]
        pub struct $name {
            directive: Directive,
        }

        impl $name {
            #[inline]
            pub fn new() -> Self {
                Self {
                    directive: Directive::new($directive_name),
                }
            }
        }

        impl DirectiveSpec for $name {
            const NAME: &'static str = $directive_name;

            #[inline]
            fn inner_mut(&mut self) -> &mut Directive {
                &mut self.directive
            }

            #[inline]
            fn build(self) -> Directive {
                self.directive
            }
        }
    };
}

define_directive!(DefaultSrc, constants::DEFAULT_SRC);
define_directive!(ScriptSrc, constants::SCRIPT_SRC);
define_directive!(StyleSrc, constants::STYLE_SRC);
define_directive!(ImgSrc, constants::IMG_SRC);
define_directive!(ConnectSrc, constants::CONNECT_SRC);
define_directive!(FontSrc, constants::FONT_SRC);
define_directive!(ObjectSrc, constants::OBJECT_SRC);
define_directive!(MediaSrc, constants::MEDIA_SRC);
define_directive!(FrameSrc, constants::FRAME_SRC);
define_directive!(WorkerSrc, constants::WORKER_SRC);
define_directive!(ManifestSrc, constants::MANIFEST_SRC);
define_directive!(ChildSrc, constants::CHILD_SRC);
define_directive!(FrameAncestors, constants::FRAME_ANCESTORS);
define_directive!(BaseUri, constants::BASE_URI);
define_directive!(FormAction, constants::FORM_ACTION);
define_directive!(ScriptSrcElem, constants::SCRIPT_SRC_ELEM);
define_directive!(ScriptSrcAttr, constants::SCRIPT_SRC_ATTR);
define_directive!(StyleSrcElem, constants::STYLE_SRC_ELEM);
define_directive!(StyleSrcAttr, constants::STYLE_SRC_ATTR);
define_directive!(PrefetchSrc, constants::PREFETCH_SRC);

#[derive(Debug, Default, Clone)]
pub struct Sandbox {
    values: FxHashSet<Cow<'static, str>>,
}

impl Sandbox {
    #[inline]
    pub fn new() -> Self {
        Self {
            values: FxHashSet::default(),
        }
    }

    #[inline]
    pub fn allow_forms(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-forms"));
        self
    }

    #[inline]
    pub fn allow_same_origin(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-same-origin"));
        self
    }

    #[inline]
    pub fn allow_scripts(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-scripts"));
        self
    }

    #[inline]
    pub fn allow_popups(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-popups"));
        self
    }

    #[inline]
    pub fn allow_modals(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-modals"));
        self
    }

    #[inline]
    pub fn allow_orientation_lock(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-orientation-lock"));
        self
    }

    #[inline]
    pub fn allow_pointer_lock(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-pointer-lock"));
        self
    }

    #[inline]
    pub fn allow_presentation(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-presentation"));
        self
    }

    #[inline]
    pub fn allow_popups_to_escape_sandbox(mut self) -> Self {
        self.values
            .insert(Cow::Borrowed("allow-popups-to-escape-sandbox"));
        self
    }

    #[inline]
    pub fn allow_top_navigation(mut self) -> Self {
        self.values.insert(Cow::Borrowed("allow-top-navigation"));
        self
    }

    pub fn add_value(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.values.insert(value.into());
        self
    }

    pub fn build(self) -> Directive {
        let mut directive = Directive::new(constants::SANDBOX);
        for value in self.values {
            directive.add_source(Source::Host(value));
        }
        directive
    }
}
