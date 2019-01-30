from python_digest import calculate_partial_digest

from django_digest import get_backend, get_setting, DEFAULT_REALM
from django_digest.models import PartialDigest


class DigestApi:
    _postponed_partial_digests = {}

    @classmethod
    def _get_logins(cls, user, method_name):
        login_factory = get_backend('DIGEST_LOGIN_FACTORY',
                                    'django_digest.DefaultLoginFactory')
        method = getattr(login_factory, method_name, None)
        if method:
            return set(method(user))
        else:
            return set()

    @classmethod
    def _confirmed_logins(cls, user):
        return cls._get_logins(user, 'confirmed_logins_for_user')

    @classmethod
    def _unconfirmed_logins(cls, user):
        return cls._get_logins(user, 'unconfirmed_logins_for_user')

    @classmethod
    def _store_partial_digests(cls, user):
        PartialDigest.objects.filter(user=user).delete()
        for (login, partial_digest, confirmed) in (
                cls._postponed_partial_digests[user.password]):
            PartialDigest.objects.create(user=user, login=login, confirmed=confirmed,
                                         partial_digest=partial_digest)

    @classmethod
    def _prepare_partial_digests(cls, user, raw_password):
        if raw_password is None:
            return
        realm = get_setting('DIGEST_REALM', DEFAULT_REALM)
        partial_digests = []
        for (confirmed, factory_method) in ((True, cls._confirmed_logins),
                                            (False, cls._unconfirmed_logins)):
            partial_digests += [(login, calculate_partial_digest(login, realm,
                                                                 raw_password), confirmed)
                                for login in factory_method(user)]

        password_hash = user.password
        cls._postponed_partial_digests[password_hash] = partial_digests

    @classmethod
    def _review_partial_digests(cls, user):
        confirmed_logins = cls._confirmed_logins(user)
        unconfirmed_logins = cls._unconfirmed_logins(user)

        for pd in PartialDigest.objects.filter(user=user):
            if pd.login in confirmed_logins:
                if not pd.confirmed:
                    pd.confirmed = True
                    pd.save()
            elif pd.login in unconfirmed_logins:
                if pd.confirmed:
                    pd.confirmed = False
                    pd.save()
            else:
                pd.delete()

    @classmethod
    def _after_authenticate(cls, user, password):
        for (confirmed, factory_method) in ((True, cls._confirmed_logins),
                                            (False, cls._unconfirmed_logins)):
            logins = factory_method(user)
            # if we don't have all of these logins
            # and exactly these logins in the database
            db_logins = set(
                [pd.login for pd in PartialDigest.objects.filter(user=user,
                                                                 confirmed=confirmed)])
            if db_logins != logins:
                cls._prepare_partial_digests(user, password)
                cls._persist_partial_digests(user)
                return

    @classmethod
    def _persist_partial_digests(cls, user):
        password_hash = user.password
        if password_hash in cls._postponed_partial_digests:
            cls._store_partial_digests(user)
            del cls._postponed_partial_digests[password_hash]

    @classmethod
    def _post_save_persist_partial_digests(cls, sender, instance=None, **kwargs):
        if instance is not None:
            cls._persist_partial_digests(instance)


post_save_callback = DigestApi._post_save_persist_partial_digests
