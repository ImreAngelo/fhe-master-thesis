<h1>(Somewhat) Practical Anonymous Routing with Homomorphic Encryption</h1>
<div style="text-align: center">
    Description
</div>

<h2>Table of Contents</h2>
<ul>
    <li><a href="#build">Build Instructions</a></li>
</ul>

<h2 id="#build">Build Instructions</h2>

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