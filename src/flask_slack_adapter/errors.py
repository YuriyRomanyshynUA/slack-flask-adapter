
class SlackAdapterError(Exception):

    def __init__(self, msg, payload=None, **kwargs):
        super().__init__(msg)
        self.msg = msg
        self.__dict__.update(kwargs)

        # deleting verification token to prevent it exposing
        if payload:
            self.payload = dict(**payload)
            self.payload['token'] = None

    def __str__(self):
        tmp = "\n".join(
            f"{k}: {v}"
            for k, v in self.__dict__.items()
        )
        return (
            f"\n<SlackAdapterError> exception:\n{tmp}\n"
        )

    def __repr__(self):
        return self.__str__()


class SlackAdapterVerificationError(SlackAdapterError):
    pass


class SlackAdapterValidationError(SlackAdapterError):

    def __init__(self, msg, errors, **kwargs):
        kwargs.update({"errors": errors})
        super().__init__(msg, **kwargs)
