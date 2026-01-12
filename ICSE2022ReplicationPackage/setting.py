import sys
import os

# config your working folder and the correponding folder
WORK_DIR = r'c:\Users\lxp\Desktop\V-SZZ-main\ICSE2022ReplicationPackage'

REPOS_DIR = r'c:\Users\lxp\Desktop\V-SZZ-main\repos'  # 需要创建这个文件夹存放Git仓库

DATA_FOLDER = os.path.join(WORK_DIR, 'data')

SZZ_FOLDER = os.path.join(WORK_DIR, 'icse2021-szz-replication-package')

DEFAULT_MAX_CHANGE_SIZE = sys.maxsize

AST_MAP_PATH = os.path.join(WORK_DIR, 'ASTMapEval_jar')

LOG_DIR = os.path.join(WORK_DIR, 'GitLogs')