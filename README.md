<h2>aws-deploy</h2>

<h3>Author: Abhinav Bichal</h3>

<p>This is the tool that I use to deploy any of the services I work on on AWS.</p>

<h3>About aws-deploy</h3>
<p><strong>Why did I make aws-deploy?</strong></p>
<ul>
    <li>Deploy services programatically to ensure reproducibility and consistency across platforms</li>
    <li>Get comprehensive details about each step of deployment and avoid "black box" logic</li>
    <li>And honestly just to learn a bit more about AWS and the more technical details about it</li>
</ul>

<h3>Getting Started</h3>

<p>Before using aws-deploy, first ensure that you are signed in for AWS. Either using the AWS CLI or writing in the details of the account manually.</p>

<i>Using the AWS CLI</i>
```
aws configure
# follow the prompt after
```

<i>Manually:</i>
~/.aws/credentials
```
[default]
aws_acess_key_id=<ACCESS_KEY_ID>
aws_secret_access_key=<SECRET_ACCESS_KEY>
```

<p>Also ensure that this AWS account has general settings for the service you want deployed allowed (or else aws-deploy will not work).</p>

<p>With the settings properly configured, boto3 is able to work properly and this API will effectively use boto3 as a wrapper for its function calls</p>

<h3>Using aws-deploy</h3>