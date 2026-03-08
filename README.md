<h1>(Somewhat) Practical Anonymous Routing with Homomorphic Encryption</h1>
<div style="text-align: center">
    Many anonymous communication systems have been proposed and implemented with the goal of allowing users to exchange messages over a network without revealing who is communicating with whom. Most of these designs (e.g. Tor, I2P, mixnets) rely on the <span style="text-style: italic">threshold model</span> to provide anonymity, wherein some components of their infrastructure must be behaving honestly. Systems with stronger anonymity guarantees (e.g. DC-nets) generally suffer from poor scalability.

    Some recent works have focused on creating anonymous communication systems that provide unconditional sender anonymity, even through untrusted or adversarial networks. This report explores one such proposal, sPAR, which uses fully homomorphic encryption to allow an untrusted server to shuffle encrypted messages without learning the underlying permutation. 

    The report proposes a master thesis with the goal of evaluating the practicality of the design by providing a full implementation of sPAR, analysing its performance, and studying how well it scales to large networks.
</div>

<h2>Table of Contents</h2>
<ul>
    <li><a href="#build">Build Instructions</a></li>
    <li><a href="#structure">Project Structure</a></li>
</ul>

<h2 id="build">Build Instructions</h2>

1. Clone the repo and initialize submodules recursively
2. Run `make build` to build the project
3. Profit

> [!IMPORTANT]
> ```
> make build
> ```

> [!TIP]
> The project will statically link OpenFHE by default. 
> To build the project using a version of OpenFHE already installed on the system, run `make build-dynamic`


<h2 id="structure">Project Structure</h2>