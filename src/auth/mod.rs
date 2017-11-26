use std::collections::{hash_set, HashSet};
use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, Unexpected, Visitor};

pub use self::authentication::{ApplicationSecrets, AuthenticationFlow, BearerToken};
pub use self::authorization::{AuthorizationDuration, AuthorizationResponseType,
                              AuthorizationUrlBuilder, AuthorizationUrlError};

mod authentication;
mod authorization;

/// An OAuth scope for specifying access needed for a user account.
///
/// Scopes are used to add access for specific resources and functionality for a given user account.
/// Scopes do not _remove_ access.
///
/// The `All` scope can be used to request _full_ access for a user's account and is equivalent to
/// including all other scopes in the request.
///
/// By default, `Identity` is the only scope used during authorization and authentication.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    /// Allow access to all resources for a user.
    All,
    /// Update preferences and account information. Does not have access to email or password.
    Account,
    /// Spend reddit gold creddits by giving gold to others.
    Creddits,
    /// Edit/delete comments and submissions.
    Edit,
    /// Select subreddit flair and change link flair.
    Flair,
    /// Access voting history and saved/hidden comments and submissions.
    History,
    /// Access reddit username and signup date.
    Identity,
    /// Manage settings and contributors of live threads.
    LiveManage,
    /// Manage the configuration, sidebar, and CSS.
    ModConfig,
    /// Add/remove users as approved submitters, ban/unban or mute/unmute users.
    ModContributors,
    /// Manage and assign flair.
    ModFlair,
    /// Access moderation logs.
    ModLog,
    /// Access/manage modmail via mod.reddit.com.
    ModMail,
    /// Invite/remove other moderators.
    ModOthers,
    /// Approve/remove/distinguish content and mark content as NSFW.
    ModPosts,
    /// Change own moderation or contributor status for a subreddit.
    ModSelf,
    /// Access traffic stats.
    ModTraffic,
    /// Change editors and visibility of wiki pages.
    ModWiki,
    /// Access the list of subreddits being moderated, contributed to, or subscribed to by the user.
    MySubreddits,
    /// Access the inbox and send private messages.
    PrivateMessages,
    /// Access posts and comments by the user.
    Read,
    /// Report content for rules violations and hide/show individual submissions.
    Report,
    /// Save/unsave comments and submissions.
    Save,
    /// Edit structured styles.
    StructuredStyles,
    /// Submit links and comments.
    Submit,
    /// Manage subreddit subscriptions and friends.
    Subscribe,
    /// Submit/change comment and submission votes.
    Vote,
    /// Edit wiki pages.
    WikiEdit,
    /// Read wiki pages.
    WikiRead,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let scope = match *self {
            Scope::All => "*",
            Scope::Account => "account",
            Scope::Creddits => "creddits",
            Scope::Edit => "edit",
            Scope::Flair => "flair",
            Scope::History => "history",
            Scope::Identity => "identity",
            Scope::LiveManage => "livemanage",
            Scope::ModConfig => "modconfig",
            Scope::ModContributors => "modcontributors",
            Scope::ModFlair => "modflair",
            Scope::ModLog => "modlog",
            Scope::ModMail => "modmail",
            Scope::ModOthers => "modothers",
            Scope::ModPosts => "modposts",
            Scope::ModSelf => "modself",
            Scope::ModTraffic => "modtraffic",
            Scope::ModWiki => "modwiki",
            Scope::MySubreddits => "mysubreddits",
            Scope::PrivateMessages => "privatemessages",
            Scope::Read => "read",
            Scope::Report => "report",
            Scope::Save => "save",
            Scope::StructuredStyles => "structuredstyles",
            Scope::Submit => "submit",
            Scope::Subscribe => "subscribe",
            Scope::Vote => "vote",
            Scope::WikiEdit => "wikiedit",
            Scope::WikiRead => "wikiread",
        };

        write!(f, "{}", scope)
    }
}

impl FromStr for Scope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let scope = match s {
            "*" => Scope::All,
            "account" => Scope::Account,
            "creddits" => Scope::Creddits,
            "edit" => Scope::Edit,
            "flair" => Scope::Flair,
            "history" => Scope::History,
            "identity" => Scope::Identity,
            "livemanage" => Scope::LiveManage,
            "modconfig" => Scope::ModConfig,
            "modcontributors" => Scope::ModContributors,
            "modflair" => Scope::ModFlair,
            "modlog" => Scope::ModLog,
            "modmail" => Scope::ModMail,
            "modothers" => Scope::ModOthers,
            "modposts" => Scope::ModPosts,
            "modself" => Scope::ModSelf,
            "modtraffic" => Scope::ModTraffic,
            "modwiki" => Scope::ModWiki,
            "mysubreddits" => Scope::MySubreddits,
            "privatemessages" => Scope::PrivateMessages,
            "read" => Scope::Read,
            "report" => Scope::Report,
            "save" => Scope::Save,
            "structuredstyles" => Scope::StructuredStyles,
            "submit" => Scope::Submit,
            "subscribe" => Scope::Subscribe,
            "vote" => Scope::Vote,
            "wikiedit" => Scope::WikiEdit,
            "wikiread" => Scope::WikiRead,
            _ => return Err(format!("unknown scope {}", s)),
        };

        Ok(scope)
    }
}

/// A wrapper type for `HashSet<Scope>`.
///
/// # Examples
///
/// ```
/// use snoo::auth::{Scope, ScopeSet};
///
/// let mut scope_set = ScopeSet::new();
///
/// // add some Scopes
/// scope_set.insert(Scope::Identity);
/// scope_set.insert(Scope::Account);
/// scope_set.insert(Scope::History);
///
/// // check for a specific Scope
/// if !scope_set.contains(Scope::Submit) {
///     println!("Got {} scopes, but Scope::Submit ain't one.", scope_set.len());
/// }
///
/// // remove a Scope
/// scope_set.remove(Scope::History);
///
/// // iterate over all the Scopes
/// for scope in scope_set.iter() {
///     println!("{}", scope);
/// }
/// ```
///
/// A `ScopeSet` with a fixed list of `Scope`s can be initialized from an array.
///
/// ```
/// use snoo::auth::{Scope, ScopeSet};
/// let scope_set: ScopeSet = [Scope::Identity, Scope::Account, Scope::History]
///     .iter()
///     .cloned()
///     .collect();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSet(HashSet<Scope>);

impl ScopeSet {
    /// Creates an empty set.
    ///
    /// If you just want the default `ScopeSet` containing `Scope::Identity`, use the `Default`
    /// trait implementation, instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::ScopeSet;
    /// let mut scope_set = ScopeSet::new();
    /// ```
    pub fn new() -> ScopeSet {
        ScopeSet(HashSet::new())
    }

    /// Returns true if the set contains no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// assert!(scope_set.is_empty());
    ///
    /// scope_set.insert(Scope::Identity);
    /// assert!(!scope_set.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of elements in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// assert_eq!(scope_set.len(), 0);
    /// scope_set.insert(Scope::Identity);
    /// assert_eq!(scope_set.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Adds a value to the set.
    ///
    /// If the set did not have this value present, `true` is returned. If the set did have this
    /// value present, false is returned.
    ///
    /// Inserting [`Scope::All`] will clear the set before insertion, ensuring that `Scope::All` is
    /// the only item in the set. Due to this behavior, inserting `Scope::All` will  always return
    /// true.
    ///
    /// [`Scope::All`]: enum.Scope.html#variant.All
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    ///
    /// assert_eq!(scope_set.insert(Scope::Identity), true);
    /// assert_eq!(scope_set.insert(Scope::Identity), false);
    /// assert_eq!(scope_set.insert(Scope::Account), true);
    /// assert_eq!(scope_set.len(), 2);
    /// assert_eq!(scope_set.insert(Scope::All), true);
    /// assert_eq!(scope_set.len(), 1);
    /// ```
    pub fn insert(&mut self, scope: Scope) -> bool {
        if scope == Scope::All {
            self.clear();
        }

        self.0.insert(scope)
    }

    /// Removes a value from the set. Returns `true` if the value was present in the set.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// scope_set.insert(Scope::Identity);
    ///
    /// assert_eq!(scope_set.remove(Scope::Identity), true);
    /// assert_eq!(scope_set.remove(Scope::Identity), false);
    /// assert!(scope_set.is_empty());
    /// ```
    pub fn remove(&mut self, scope: Scope) -> bool {
        self.0.remove(&scope)
    }

    /// Removes and returns the value in the set, if any, that is equal to the given one.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// scope_set.insert(Scope::Identity);
    ///
    /// assert_eq!(scope_set.take(Scope::Identity), Some(Scope::Identity));
    /// assert_eq!(scope_set.take(Scope::Identity), None);
    /// ```
    pub fn take(&mut self, scope: Scope) -> Option<Scope> {
        self.0.take(&scope)
    }

    /// Returns `true` if the set contains a value.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// assert!(!scope_set.contains(Scope::Identity));
    ///
    /// scope_set.insert(Scope::Identity);
    /// assert!(scope_set.contains(Scope::Identity));
    /// ```
    pub fn contains(&self, scope: Scope) -> bool {
        self.0.contains(&scope)
    }

    /// Clears the set, removing all values.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// scope_set.insert(Scope::Identity);
    /// scope_set.insert(Scope::Account);
    /// scope_set.insert(Scope::History);
    /// assert!(!scope_set.is_empty());
    ///
    /// scope_set.clear();
    /// assert!(scope_set.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// An iterator visiting all elements in arbitrary order.
    ///
    /// # Examples
    ///
    /// ```
    /// use snoo::auth::{Scope, ScopeSet};
    ///
    /// let mut scope_set = ScopeSet::new();
    /// scope_set.insert(Scope::Identity);
    /// scope_set.insert(Scope::Account);
    /// scope_set.insert(Scope::History);
    ///
    /// // Will print in arbitrary order.
    /// for scope in scope_set.iter() {
    ///     println!("{}", scope);
    /// }
    /// ```
    pub fn iter(&self) -> hash_set::Iter<Scope> {
        self.0.iter()
    }
}

impl Default for ScopeSet {
    fn default() -> Self {
        ScopeSet([Scope::Identity].iter().cloned().collect())
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        ScopeSet(HashSet::from_iter(iter))
    }
}

impl IntoIterator for ScopeSet {
    type Item = Scope;
    type IntoIter = hash_set::IntoIter<Scope>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Serialize for ScopeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut scope_vec = self.0.iter().cloned().collect::<Vec<Scope>>();
        scope_vec.sort();
        let scope_string = scope_vec.iter().fold(
            String::new(),
            |mut accumulator, scope| {
                if !accumulator.is_empty() {
                    accumulator.push(' ');
                }

                accumulator + scope.to_string().as_str()
            },
        );
        serializer.serialize_str(scope_string.as_str())
    }
}

struct ScopesVisitor;

impl<'de> Visitor<'de> for ScopesVisitor {
    type Value = ScopeSet;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a string containing known scopes")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.split_whitespace()
            .map(|scope_str| Scope::from_str(scope_str))
            .collect::<Result<ScopeSet, String>>()
            .map_err(|_| de::Error::invalid_value(Unexpected::Str(v), &self))
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ScopesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde_urlencoded;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct ScopesSerdeTestContainer {
        scope: ScopeSet,
    }

    #[test]
    fn scopes_default_contains_identity() {
        let actual = ScopeSet::default();
        let expected = ScopeSet([Scope::Identity].iter().cloned().collect());

        assert_eq!(actual, expected);
    }

    #[test]
    fn serializes_known_scopes() {
        let scopes_container = ScopesSerdeTestContainer {
            scope: [Scope::Account, Scope::History, Scope::Identity]
                .iter()
                .cloned()
                .collect(),
        };

        let actual = serde_urlencoded::to_string(scopes_container).unwrap();
        let expected = "scope=account+history+identity";

        assert_eq!(actual.as_str(), expected)
    }

    #[test]
    fn deserializes_known_scopes() {
        let actual = serde_urlencoded::from_str::<ScopesSerdeTestContainer>(
            "scope=account+history+identity",
        ).unwrap();
        let expected = ScopesSerdeTestContainer {
            scope: [Scope::Account, Scope::History, Scope::Identity]
                .iter()
                .cloned()
                .collect(),
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn fails_to_deserialize_unknown_scopes() {
        let result = serde_urlencoded::from_str::<ScopesSerdeTestContainer>("scope=unknown");
        assert!(result.is_err())
    }
}
