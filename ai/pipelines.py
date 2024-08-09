'''
This module contains the base classes for the different Pipelines, which are used to process the user's question.
'''

import abc
import os
import typing

import gci.componentmodel
import instructor
from langfuse.openai import AzureOpenAI
import pydantic

OPEN_AI_MODEL: str = os.getenv("OPEN_AI_MODEL")  # type: ignore
client = instructor.from_openai(AzureOpenAI())


# Base Classes which are returned by the different Pipelines
class PackageID(pydantic.BaseModel):
    name: str = pydantic.Field(description="Name of the Package.")
    version: str | None = pydantic.Field(description="Version of the Package.")

    class Config:
        frozen = True


class ResourceID(pydantic.BaseModel):
    name: str = pydantic.Field(description="Name of the Resource.")
    version: str | None = pydantic.Field(description="Version of the Resource.")

    class Config:
        frozen = True


class BasePypeline(abc.ABC):
    @abc.abstractmethod
    def run(
        self, question: str
    ) -> (
        dict[str, str | list[gci.componentmodel.ComponentIdentity]]
        | dict[str, str | list[PackageID]]
    ):
        pass


class PipelineManager:

    def __init__(self) -> None:
        self.pipelines: dict[str, BasePypeline] = {}

    def add_pipeline(self, name: str, pypeline: BasePypeline):
        if name in self.pipelines.keys():
            raise KeyError(f"Pipeline with name {name} already exists.")
        self.pipelines[name] = pypeline

    def get_pipeline(self, name: str):
        if name in self.pipelines.keys():
            return self.pipelines[name]
        raise KeyError(f"No pipeline with name {name} available.")

    def run_pipeline(self, name: str, question: str):
        if name in self.pipelines.keys():
            return self.pipelines[name].run(question)
        raise KeyError(f"No pipeline with name {name} available.")

    def decide_which_pipeline(self, question) -> BasePypeline:
        class PipelineDecision(pydantic.BaseModel):
            pipeline: typing.Literal[*tuple(self.pipelines.keys())] = pydantic.Field(
                description="Describes, which kind of data, the user wants at the end. Depending on this, the right Pipeline will be chosen to process the question."
            )

        pipelne_decision = client.chat.completions.create(
            model=OPEN_AI_MODEL,
            temperature=0.0,
            response_model=PipelineDecision,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Pipeline manager. Your task is to analyze the question of the user and"
                        " select the right Pipeline to process and answer the Question.\n"
                        " At the end of of processing, the output will be a list of one of the following entity Types:\n"
                        "<entity-types>\n"
                        f"  {self.pipelines.keys()}"
                        "</entity-types>\n"
                        "\n"
                        " The pipelines have the name of the entity-type, they will return in the end."
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        return self.pipelines[pipelne_decision.pipeline]
