class AnalysisModule(object):

    def __init__(self, config_section, *args, **kwargs):
        assert isinstance(config_section, str)
        self.config = config_section

    def analyze_sample(self, filepath='', tags=[]):
        '''
        Called to start the analysis for the module.

        :param filepath: The full path and filename of the sample to analyze.
        :type filepath: str
        :param tags: Any tags associated with the given sample
        :type tags: list
        '''
        raise NotImplementedError("This analysis module was not implemented.")

    def check_status(self, filename='', tags=[]):
        '''
        Returns the status of the analysis module for the given file

        :param filepath: The full path and filename of the sample to analyze.
        :type filepath: str
        :param tags: Any tags associated with the given sample
        :type tags: list
        :returns: boolean
        '''
        raise NotImplementedError("This analysis module was not implemented.")

    def cleanup(self, filename='', tags=[]):
        '''
        Called to perform any necessary cleanup.

        :param filepath: The full path and filename of the sample to analyze.
        :type filepath: str
        :param tags: Any tags associated with the given sample
        :type tags: list
        '''
        raise NotImplementedError("This analysis module was not implemented.")
