#小镜像
FROM python:3.9-alpine3.19
COPY . /app
WORKDIR /app
#配置国内阿里源
RUN pip config set global.index-url http://mirrors.aliyun.com/pypi/simple/
RUN pip config set global.trusted-host mirrors.aliyun.com

#安装pipreqs,解决依赖,生成requirements.txt
RUN pip install pipreqs
RUN pipreqs /app --force
#安装依赖
RUN pip install -r /app/requirements.txt

# 指定这个容器启动的时候要运行的命令，可以追加命令
ENTRYPOINT ["python"]
CMD ["dns-txt-proxy.py"]
