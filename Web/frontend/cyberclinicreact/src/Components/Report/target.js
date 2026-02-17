
export function TargetList ({targets}) {
    return (
        <ul>
            {targets.map((target, index) => (
                <li key={index}>
                    {target.target_name}({target.target_value}) - {target.target_type}
                </li>
            ))}
        </ul>
    )
};

export function TargetTable ({targets}) {
    return (
        <table>
            <thead>
                <tr>
                    <th>Targets</th>
                </tr>
                <tr>
                    <th>Target Name</th>
                    <th>Target Address</th>
                    <th>Target Type</th>
                </tr>
            </thead>
            <tbody>
                {targets.map((target, index) => (
                    <tr key={index}>
                        <td>{target.target_name}</td>
                        <td>{target.target_value}</td>
                        <td>{target.target_type}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    )
};