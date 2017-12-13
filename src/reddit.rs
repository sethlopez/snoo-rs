use std::fmt;

use auth::Scope;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Resource {
    // Account
    Me,
    MeKarma,
    MePrefs,
    MeTrophies,
    PrefsBlocked,
    PrefsFriends,
    PrefsMessaging,
    PrefsTrusted,
    // Subreddits
    SubredditAbout(String),
    SubredditAboutBanned(String),
    SubredditAboutContributors(String),
    SubredditAboutModerators(String),
    SubredditAboutMuted(String),
    SubredditAboutWikiBanned(String),
    SubredditAboutWikiContributors(String),
    // Auth
    AccessToken,
    Authorize,
    AuthorizeCompact,
}

impl Resource {
    pub fn scope(&self) -> Option<Scope> {
        match *self {
            Resource::Me | Resource::MePrefs | Resource::MeTrophies => Scope::Identity.into(),
            Resource::MeKarma => Scope::MySubreddits.into(),
            Resource::PrefsBlocked |
            Resource::PrefsFriends |
            Resource::PrefsMessaging |
            Resource::PrefsTrusted |
            Resource::SubredditAbout(_) |
            Resource::SubredditAboutBanned(_) |
            Resource::SubredditAboutContributors(_) |
            Resource::SubredditAboutModerators(_) |
            Resource::SubredditAboutMuted(_) |
            Resource::SubredditAboutWikiBanned(_) |
            Resource::SubredditAboutWikiContributors(_) => Scope::Read.into(),
            _ => None,
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let base_url = match *self {
            Resource::AccessToken |
            Resource::Authorize |
            Resource::AuthorizeCompact => "https://www.reddit.com",
            _ => "https://oauth.reddit.com",
        };
        match *self {
            // Account
            Resource::Me => write!(f, "{}/api/v1/me", base_url),
            Resource::MeKarma => write!(f, "{}/api/v1/me/karma", base_url),
            Resource::MePrefs => write!(f, "{}/api/v1/me/prefs", base_url),
            Resource::MeTrophies => write!(f, "{}/api/v1/me/trophies", base_url),
            Resource::PrefsBlocked => write!(f, "{}/prefs/blocked", base_url),
            Resource::PrefsFriends => write!(f, "{}/prefs/friends", base_url),
            Resource::PrefsMessaging => write!(f, "{}/prefs/messaging", base_url),
            Resource::PrefsTrusted => write!(f, "{}/prefs/trusted", base_url),
            // Subreddits
            Resource::SubredditAbout(ref subreddit) => {
                write!(f, "{}/r/{}/about", base_url, subreddit)
            }
            Resource::SubredditAboutBanned(ref subreddit) => {
                write!(f, "{}/r/{}/about/banned", base_url, subreddit)
            }
            Resource::SubredditAboutContributors(ref subreddit) => {
                write!(f, "{}/r/{}/about/contributors", base_url, subreddit)
            }
            Resource::SubredditAboutModerators(ref subreddit) => {
                write!(f, "{}/r/{}/about/moderators", base_url, subreddit)
            }
            Resource::SubredditAboutMuted(ref subreddit) => {
                write!(f, "{}/r/{}/about/muted", base_url, subreddit)
            }
            Resource::SubredditAboutWikiBanned(ref subreddit) => {
                write!(f, "{}/r/{}/about/wikibanned", base_url, subreddit)
            }
            Resource::SubredditAboutWikiContributors(ref subreddit) => {
                write!(f, "{}/r/{}/about/wikicontributors", base_url, subreddit)
            }
            // Auth
            Resource::AccessToken => write!(f, "{}/api/v1/access_token", base_url),
            Resource::Authorize => write!(f, "{}/api/v1/authorize", base_url),
            Resource::AuthorizeCompact => write!(f, "{}/api/v1/authorize.compact", base_url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_resource_displays_as_the_correct_url() {
        let actual = format!("{}", Resource::AccessToken);
        let expected = "https://www.reddit.com/api/v1/access_token".to_owned();
        assert_eq!(actual, expected);
    }

    #[test]
    fn access_token_resource_does_not_require_a_scope() {
        let actual = Resource::AccessToken.scope();
        let expected = None;
        assert_eq!(actual, expected);
    }

    #[test]
    fn about_me_resource_displays_as_the_correct_url() {
        let actual = format!("{}", Resource::Me);
        let expected = "https://oauth.reddit.com/api/v1/me".to_owned();
        assert_eq!(actual, expected);
    }

    #[test]
    fn about_me_resource_requires_a_scope() {
        let actual = Resource::Me.scope();
        let expected = Some(Scope::Identity);
        assert_eq!(actual, expected);
    }

    #[test]
    fn subreddit_about_resource_displays_as_the_correct_url() {
        let resource = Resource::SubredditAbout("all".to_owned());
        let actual = format!("{}", resource);
        let expected = "https://oauth.reddit.com/r/all/about".to_owned();
        assert_eq!(actual, expected);
    }

    #[test]
    fn subreddit_about_resource_requires_a_scope() {
        let resource = Resource::SubredditAbout("all".to_owned());
        let actual = resource.scope();
        let expected = Some(Scope::Read);
        assert_eq!(actual, expected);
    }
}
