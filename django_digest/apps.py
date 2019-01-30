from django.apps import AppConfig
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save

from django_digest.signals import DigestApi, post_save_callback


class DjangoDigestConfig(AppConfig):
    name = 'django_digest'
    digest_api = None

    def __init__(self, app_name, app_module):
        super(DjangoDigestConfig, self).__init__(app_name, app_module)
        self.digest_api = DigestApi()

    def ready(self):

        _user_model = get_user_model()
        _old_set_password = _user_model.set_password
        _old_check_password = _user_model.check_password
        _old_authenticate = ModelBackend.authenticate

        def _new_check_password(user, raw_password):
            result = _old_check_password(user, raw_password)
            if result:
                self.digest_api._after_authenticate(user, raw_password)
            return result

        def _new_authenticate(backend, username=None, password=None):
            user = _old_authenticate(backend, username, password)
            if user:
                self.digest_api._after_authenticate(user, password)
            return user

        def _new_set_password(user, raw_password):
            _old_set_password(user, raw_password)
            self.digest_api._prepare_partial_digests(user, raw_password)

        _user_model.check_password = _new_check_password
        _user_model.set_password = _new_set_password
        ModelBackend.authenticate = _new_authenticate

        post_save.connect(post_save_callback, sender=_user_model)
