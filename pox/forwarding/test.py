
import imp
OptNet = imp.load_source('OpticalNetwork', 'optical_network/src/main/OpticalNetwork.py')

if "__main__" == __name__:
    opt_net = OptNet.get_running_opt_net()
    print("DEBUG")
