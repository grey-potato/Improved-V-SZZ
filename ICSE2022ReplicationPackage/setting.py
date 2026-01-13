import sys
import os

# 动态获取工作目录（当前文件所在目录）
WORK_DIR = os.path.dirname(os.path.abspath(__file__))

# 项目根目录（ICSE2022ReplicationPackage的父目录）
PROJECT_ROOT = os.path.dirname(WORK_DIR)

REPOS_DIR = os.path.join(PROJECT_ROOT, 'repos')  # Git仓库存放目录

DATA_FOLDER = os.path.join(WORK_DIR, 'data')

SZZ_FOLDER = os.path.join(WORK_DIR, 'icse2021-szz-replication-package')

DEFAULT_MAX_CHANGE_SIZE = sys.maxsize

AST_MAP_PATH = os.path.join(WORK_DIR, 'ASTMapEval_jar')

LOG_DIR = os.path.join(WORK_DIR, 'GitLogs')