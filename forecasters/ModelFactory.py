import logging
from typing import Callable

from .ModelBase import ModelBase

logger = logging.getLogger(__name__)


class ModelFactory:
    """ The factory class for creating models"""

    registry = {}
    """ Internal registry for available models"""

    @classmethod
    def register(cls, name: str) -> Callable:
        """ Class method to register Executor class to the internal registry.
        Args:
            name (str): The name of the executor.
        Returns:
            The Executor class itself.
        """

        def inner_wrapper(wrapped_class: ModelBase) -> ModelBase:
            if name in cls.registry:
                logger.warning('Model %s already exists. Will replace it', name)
            cls.registry[name] = wrapped_class

            return wrapped_class

        return inner_wrapper

    @classmethod
    def create_model(cls, name: str, **kwargs) -> ModelBase:
        """ Factory command to create the executor.
        This method gets the appropriate Executor class from the registry
        and creates an instance of it, while passing in the parameters
        given in ``kwargs``.
        Args:
            name (str): The name of the executor to create.
        Returns:
            An instance of the executor that is created.
        """

        if name not in cls.registry:
            raise ValueError('model {} does not exist in the registry'.format(name))

        exec_class = cls.registry[name]
        executor = exec_class(**kwargs)
        return executor
