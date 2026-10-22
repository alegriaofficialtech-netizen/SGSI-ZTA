from pydantic import Field, SecretStr

from app.schemas.identity import InputModel


class ChallengeInput(InputModel):
    challenge_token: SecretStr = Field(min_length=32, max_length=128)


class VerifyInput(ChallengeInput):
    code: SecretStr = Field(min_length=6, max_length=40)
    recovery: bool = False


class FactorConfirmation(InputModel):
    password: SecretStr = Field(min_length=1, max_length=128)
    code: SecretStr = Field(min_length=6, max_length=6)
