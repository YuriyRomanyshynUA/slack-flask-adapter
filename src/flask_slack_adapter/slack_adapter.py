import os
import sys
import json
import yaml
# from urllib.parse import urlencode
from copy import deepcopy
from pathlib import Path
from functools import wraps

from slack import WebClient
from slack.errors import SlackApiError

from flask_slack_adapter.errors import SlackAdapterError
from flask_slack_adapter.errors import SlackAdapterValidationError
from flask_slack_adapter.errors import SlackAdapterVerificationError


__all__ = ['SlackAdapter']


class PAYLOAD_TYPES:
    BLOCK_ACTIONS = "block_actions"
    MESSAGE_ACTIONS = "message_action"
    VIEW_SUBMISSION = "view_submission"
    VIEW_CLOSE = "view_close"


def get_root_path(import_name):
    mod = sys.modules.get(import_name)
    if mod is not None and hasattr(mod, "__file__"):
        return os.path.dirname(
            os.path.abspath(mod.__file__)
        )


class SlackAdapter:

    def __init__(
        self,
        app,
        request_url=None,
        options_url=None,
        views_folder=None
    ):
        # ================================
        self._app = app
        self._request_url = request_url
        self._options_url = options_url
        self._views_folder = views_folder
        self._views = {}
        self._option_action_handlers = {}
        self._message_action_handler = None
        self._view_submission_handlers = {
            "callback_id": {},
            "default": None,
            "filters": {}
        }
        self._view_close_handlers = {
            "callback_id": {},
            "default": None,
            "filters": {}
        }
        self._block_action_handlers = {
            "action_block_id": {},
            "action_id": {},
            "filters": {},
            "default": None
        }
        # ================================
        assert self._app.config.get("SIGNING_KEY") is not None, (
            "Did you forget to provide SIGNING_KEY for "
            "request body validation ?"
        )
        # ================================
        self._views_folder = Path(self._app.root_path) / self._views_folder

        assert self._views_folder.exists(), (
            f"{self._views_folder} does not exists"
        )
        assert self._views_folder.is_dir(), (
            f"{self._views_folder} is not a dir"
        )
        self._load_views()
        # ================================
        slack_token = (
            os.environ.get('SLACK_TOKEN')
            or self._app.config.get('SLACK_TOKEN')
        )
        assert slack_token is not None, (
            "Did you forget to provided slack_token "
            "to config obj or to os env ?"
        )
        self._slack_client = WebClient(
            token=slack_token
        )
        # ================================
        if request_url:
            self._app.add_url_rule(
                rule=request_url,
                view_func=self._process_request,
                methods=['POST']
            )
        if options_url:
            self._app.add_url_rule(
                rule=options_url,
                view_func=self._process_options_request,
                methods=['POST']
            )
        # ================================
        self._app.register_error_handler(
            SlackAdapterVerificationError,
            self._on_slack_verification_exception
        )
        self._app.register_error_handler(
            SlackAdapterError,
            self._on_slack_error
        )
        self._app.register_error_handler(
            SlackApiError,
            self._on_slack_api_error
        )
        self._app.register_error_handler(
            Exception,
            self._on_error
        )

    @property
    def slack_client(self):
        return self._slack_client

    @property
    def logger(self):
        return self._app.logger

    def view(self, name):
        if not self._views.get(name):
            self._load_view(name)

        assert self._views.get(name) is not None, (
            "Did not load view!"
        )
        return deepcopy(self._views[name])

    def _load_views(self):
        files = self._views_folder.glob('*.yaml')

        for f in files:
            dot_index = f.name.rindex(".")
            name = f.name[:dot_index]
            if name not in self._views:
                with f.open('r') as open_file:
                    tmp = yaml.full_load(open_file)
                    self._views[name] = tmp['view']

    def _load_view(self, name):
        files = list(self._views_folder.glob(f'{name}.yaml'))

        if not files:
            raise SlackAdapterError(
                "view with name {name} does not exist"
            )

        with files[0].open() as open_file:
            tmp = yaml.full_load(open_file)
            self._views[name] = tmp['view']

    def default_block_action(self, handler):
        self._block_action_handlers['default'] = handler
        return handler

    def register_block_action(
        self, handler, *,
        action_block_id=None,
        action_id=None,
        filter_fn=None
    ):
        assert isinstance(action_block_id or "", str), (
            "arg action_block_id must be type of str"
        )
        assert isinstance(action_id or "", str), (
            "arg action_id must be type of str"
        )
        assert callable(filter_fn or (lambda: None)), (
            "arg filter_fn must be callable"
        )
        # ===================
        # TODO:
        # better way is to make list of bool (arg is not None, ...)
        # and use any builtin function
        args_not_empty = (
            action_block_id is not None,
            action_id is not None,
            filter_fn is not None
        )
        assert args_not_empty is True, (
            "You have to provide at least one of the "
            "'block_action' decorator args"
        )
        if self._block_action_handlers['default'] is not None:
            raise SlackAdapterError("Already exist default handler!")
        # ===================
        if action_block_id:
            self._block_action_handlers['action_block_id'][action_block_id] = handler
        elif action_id:
            self._block_action_handlers['action_id'][action_id] = handler
        elif filter_fn:
            self._block_action_handlers['filters'][filter_fn] = handler

        return handler

    def block_action(self, *, action_block_id=None, action_id=None, filter_fn=None):
        def wrapper(handler):
            self.register_block_action(
                handler, action_block_id,
                action_id, filter_fn
            )
            return handler
        return wrapper

    def message_action(self, handler):
        self._message_action_handler = handler

    def default_view_submission(self, handler):
        self._view_submission_handlers['default'] = handler
        return handler

    def register_view_submission(self, handler, *, callback_id=None, filter_fn=None):
        assert isinstance(callback_id or "", str), (
            "arg callback_id must be type of str"
        )
        assert callable(filter_fn or (lambda: None)), (
            "arg filter_fn must be callable"
        )
        # ===================
        args_not_empty = (
            callback_id is not None or
            filter_fn is not None
        )
        assert args_not_empty is True, (
            "You have to provide at least one of the "
            "'view_submission' decorator args"
        )
        if self._view_submission_handlers['default'] is not None:
            raise SlackAdapterError("Already exist default handler!")
        # ===================
        if callback_id:
            self._view_submission_handlers['callback_id'][callback_id] = handler
        elif filter_fn:
            self._view_submission_handlers['filters'][filter_fn] = handler

        return handler

    def view_submission(self, *, callback_id=None, filter_fn=None):
        def wrapper(handler):
            self.register_view_submission(handler, callback_id, filter_fn)
            return handler
        return wrapper

    def default_view_close(self, handler):
        self._view_close_handler['default'] = handler
        return handler

    def register_view_close(self, handler, *, callback_id=None, filter_fn=None):
        assert isinstance(callback_id or "", str), (
            "arg callback_id must be type of str"
        )
        assert callable(filter_fn or (lambda: None)), (
            "arg filter_fn must be callable"
        )
        # ===================
        args_not_empty = (
            callback_id is not None or
            filter_fn is not None
        )
        assert args_not_empty is True, (
            "You have to provide at least one of the "
            "'view_close' decorator args"
        )
        if self._view_close_handler['default'] is not None:
            raise SlackAdapterError("Already exist default handler!")
        # ===================
        if callback_id:
            self._view_close_handlers['callback_id'][callback_id] = handler
        elif filter_fn:
            self._view_close_handlers['filters'][filter_fn] = handler

        return handler

    def view_close(self, *, callback_id=None, filter_fn=None):
        def wrapper(handler):
            self.register_view_close(handler, callback_id, filter_fn)
            return handler
        return wrapper

    def register_options_loader(self, handler, action_id):
        self._option_action_handlers[action_id] = handler

    def options_load(self, action_id):
        def wrapper(handler):
            self.register_options_loader(handler, action_id)
            return handler
        return wrapper

    def register_slack_cmd(self, handler, rule):
        @wraps(handler)
        def decorator(*args, **kwargs):
            from flask import request as r
            # \/ will raise exception if faile
            # \/ exception will be handled by appropriate error handler
            self._verify_request_signuture(r)  # < in case of this function order does matter
            # check this doc https://flask.palletsprojects.com/en/1.1.x/api/#flask.Request.get_data
            payload = r.values  # must stay after prev line of code
            return handler(payload, *args, **kwargs)

        self._app.add_url_rule(
            rule=rule,
            view_func=decorator,
            methods=['POST']
        )

    def slash_cmd(self, rule):
        def wrapper(handler):
            self.register_slack_cmd(handler, rule)
            return handler
        return wrapper

    def _verify_request_signuture(self, request):
        signing_key = self._app.config.get("SIGNING_KEY")
        request_body = request.get_data(as_text=True)
        timestamp = request.headers.get('X-Slack-Request-Timestamp')
        signature = request.headers.get('X-Slack-Signature')

        if timestamp is None or signature is None:
            raise SlackAdapterVerificationError(
                "Request does not contain required headers fields"
            )
        is_valid = self._slack_client.validate_slack_signature(
            signing_secret=signing_key,
            data=request_body,
            timestamp=timestamp,
            signature=signature
        )
        if not is_valid:
            raise SlackAdapterVerificationError(
                "X-Slack-Signature and generated signature does not match"
            )

    def _process_request(self):
        from flask import request as r

        # \/ will raise exception if faile
        # \/ exception will be handled by appropriate error handler
        self._verify_request_signuture(r)  # < in case of this function order of calls does matter
        # check this doc matter https://flask.palletsprojects.com/en/1.1.x/api/#flask.Request.get_data

        payload = json.loads(r.values['payload'])
        payload_type = payload['type']

        if payload_type == PAYLOAD_TYPES.BLOCK_ACTIONS:
            return self._process_block_action(payload)

        elif (
            payload_type == PAYLOAD_TYPES.MESSAGE_ACTIONS and
            self._message_action_handler
        ):
            return self._message_action_handler(payload)

        elif payload_type == PAYLOAD_TYPES.VIEW_SUBMISSION:
            return self._process_view_action(payload, self._view_submission_handlers)

        elif payload_type == PAYLOAD_TYPES.VIEW_CLOSE:
            return self._process_view_action(payload, self._view_close_handlers)

        return {}, 200

    def _process_block_action(self, payload):
        # action_block_id
        # action_id
        # filters
        # default
        default_handler = self._block_action_handlers['default']
        act_blc_id_handlers = self._block_action_handlers['action_block_id']
        act_ids_handlers = self._block_action_handlers['action_id']
        filters_handlers = self._block_action_handlers['filters']
        filters = list(self._block_action_handlers['filters'].keys())

        action = payload['actions'][0]
        action_block_id = action.get('block_id')
        action_id = action.get('action_id')

        if default_handler:
            return default_handler(payload)

        handler = act_blc_id_handlers.get(action_block_id)

        if handler:
            return handler(payload)

        handler = act_ids_handlers.get(action_id)

        if handler:
            return handler(payload)

        for f in filters:
            if f(payload):
                return filters_handlers[f](payload)

        return "", 200

    def _process_view_action(self, payload, handlers_storage):
        # callback_id
        # filters

        default_handler = handlers_storage['default']
        call_back_ids_handlers = handlers_storage['callback_id']
        filters_handlers = handlers_storage['filters']
        filters = list(handlers_storage['filters'].keys())

        view_callback_id = payload['view'].get('callback_id')

        if default_handler:
            return default_handler(payload)

        handler = call_back_ids_handlers.get(view_callback_id)

        if handler:
            return handler(payload) or ("", 200)

        for f in filters:
            if f(payload):
                return filters_handlers[f](payload) or ("", 200)

        return "", 200

    def _process_options_request(self):
        from flask import request as r
        # \/ will raise exception if faile
        # \/ exception will be handled by appropriate error handler
        self._verify_request_signuture(r) # < in case of this function order of calls does matter
        # check this doc matter https://flask.palletsprojects.com/en/1.1.x/api/#flask.Request.get_data

        payload = json.loads(r.values['payload'])
        action_id = payload['action_id']

        handler = self._option_action_handlers.get(action_id)

        if handler:
            tmp = handler(payload)
            return {"options": tmp}, 200

        return {"options": []}, 200

    def register_payload_validator(self, validator, handler):
        @wraps(handler)
        def decorator(*args, **kwargs):
            try:
                validator(*args, **kwargs)
            except SlackAdapterValidationError as error:
                response = dict(
                    response_action="errors",
                    errors=(getattr(error, 'errors', None) or {})
                )
                self.logger.info(
                    "Payload validation error occured in context: "
                    f"{getattr(error, 'error_context', None)} "
                    f"ERRORS: {response}"
                )
                return response, 200
            return handler(*args, **kwargs)
        return decorator

    def validate_payload(self, validator):
        def wrapper(handler):
            return self.register_payload_validator(validator, handler)
        # wrapper end
        return wrapper

    # ================================
    # Exceptions handlers \/
    # ================================

    def _on_slack_api_error(self, error):
        self.logger.exception(
            "SlackApi error occurred\n"
            f"{error}"
        )
        return "", 500

    def _on_slack_verification_exception(self, error):
        self.logger.error(
            "Verification error occurred\n"
            f"{error}"
        )
        return "Request did not pass verification", 403

    def _on_slack_error(self, error):
        self.logger.exception(
            "Slack error occurred\n"
            f"{error}"
        )
        return "Internal error", 500

    def _on_error(self, error):
        self.logger.exception(
            "Internal error\n"
            f"{error}"
        )
        return "Internal error", 500
