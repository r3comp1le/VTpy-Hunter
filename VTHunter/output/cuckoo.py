import output.analysis


class CuckooAnalysis(output.analysis.AnalysisModule):

    def __init__(self, config_section, *args, **kwargs):
        assert isinstance(config_section, str)
        self.config_section = config_section

    '''
    Called to start the analysis for the module.
    '''
    def analyze_sample(self, filename='', tags=[]):
        raise NotImplementedError("This analysis module was not implemented.")

    def check_status(self, filename='', tags=[]):
        raise NotImplementedError("This analysis module was not implemented.")

    def cleanup(self, filename='', tags=[]):
        raise NotImplementedError("This analysis module was not implemented.")
