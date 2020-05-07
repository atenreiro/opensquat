# Module: parser.py
import argparse


def validate_type(file_type):
        
    file_type = str(file_type)
    
    if (file_type != "txt") and (file_type != "json") and (file_type != "csv"):
        raise argparse.ArgumentTypeError("File format unkown!")
    return file_type

def validate_confidence(confidence_level):
    confidence_level = int(confidence_level)
    
    if confidence_level not in range(0, 5):
        raise argparse.ArgumentTypeError("confidence must be between 0 and 4")
    return confidence_level
        
def parser():
    
    
    # Parser
    parser = argparse.ArgumentParser(description="openSquat")
    parser.add_argument('-k', '--keywords', type=str, default='keywords.txt', 
                         help="keywords file (default: keywords.txt)")
    parser.add_argument('-o', '--output', type=str, default="results.txt", 
                         help="output filename (default: results.txt)")
    parser.add_argument('-c', '--confidence', type=validate_confidence, default=1, 
                         help="0 (very high), 1 (high), 2 (medium), 3 (low), 4 (very low) (default: 1)")
    parser.add_argument('-t', '--type', type=validate_type, default="txt", 
                         help="output file type [txt|json|csv] (default: txt)")
    parser.add_argument('-d', '--domains', type=str, default='domain-names.txt',
                        help='update from FILE instead of downloading new domains')
                        
    args = parser.parse_args()
    
    return args
        
        